package com.om.authing;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.types.JwtTokenStatus;
import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;


public class AuthingInterceptor implements HandlerInterceptor {
    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    @Value("${authing.app.fuxi.id}")
    String omAppId;

    @Value("${authing.app.fuxi.host}")
    String omAppHost;

    @Value("${authing.app.fuxi.secret}")
    String omAppSecret;

    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;

    @Value("${cookie.token.name}")
    private String cookieTokenName;

    @Value("${cookie.token.domains}")
    private String allowDomains;

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }

        // 检查有没有需要用户权限的注解，仅拦截AuthingToken和AuthingUserToken
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        if (!method.isAnnotationPresent(AuthingToken.class) && !method.isAnnotationPresent(AuthingUserToken.class)) {
            return true;
        }
        AuthingToken userLoginToken = method.getAnnotation(AuthingToken.class);
        AuthingUserToken authingUserToken = method.getAnnotation(AuthingUserToken.class);
        if ((userLoginToken == null || !userLoginToken.required()) && (authingUserToken == null || !authingUserToken.required())) {
            return true;
        }

        // 从请求头中取出 token
        String headerToken = httpServletRequest.getHeader("token");
        if (StringUtils.isBlank(headerToken)) {
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
            return false;
        }

        // 校验domain
        String verifyDomainMsg = verifyDomain(httpServletRequest);
        if (!verifyDomainMsg.equals("success")) {
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, verifyDomainMsg);
            return false;
        }

        // 校验cookie
        Cookie tokenCookie = verifyCookie(httpServletRequest);
        if (tokenCookie == null) {
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token miss");
            return false;
        }

        // 解密cookie中加密的token
        String token = tokenCookie.getValue();
        try {
            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
            token = RSAUtil.privateDecrypt(token, privateKey);
        } catch (Exception e) {
            tokenError(httpServletResponse, tokenCookie, "unauthorized");
            return false;
        }

        // 解析token
        String userId;
        Date issuedAt;
        Date expiresAt;
        String permission;
        String verifyToken;
        try {
            DecodedJWT decode = JWT.decode(token);
            userId = decode.getAudience().get(0);
            issuedAt = decode.getIssuedAt();
            expiresAt = decode.getExpiresAt();
            String permissionTemp = decode.getClaim("permission").asString();
            permission = new String(Base64.getDecoder().decode(permissionTemp.getBytes()));
            verifyToken = decode.getClaim("verifyToken").asString();
        } catch (JWTDecodeException j) {
            tokenError(httpServletResponse, tokenCookie, "unauthorized");
            return false;
        }

        // 校验token
        String verifyTokenMsg = verifyToken(headerToken, token, verifyToken, userId, issuedAt, expiresAt, permission);
        if (!verifyTokenMsg.equals("success")) {
            tokenError(httpServletResponse, tokenCookie, verifyTokenMsg);
            return false;
        }

        // token 用户和权限验证
        String verifyUserMsg = verifyUser(userLoginToken, userId, permission);
        if (!verifyUserMsg.equals("success")) {
            tokenError(httpServletResponse, tokenCookie, verifyUserMsg);
            return false;
        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest,
                           HttpServletResponse httpServletResponse,
                           Object o, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest,
                                HttpServletResponse httpServletResponse,
                                Object o, Exception e) throws Exception {
    }

    /**
     * 校验用户（登录状态，操作权限）
     *
     * @param userLoginToken AuthingToken（仅带有该注解的接口需要校验操作权限）
     * @param userId         用户id
     * @param permission     需要的操作权限
     * @return 校验结果
     */
    private String verifyUser(AuthingToken userLoginToken, String userId, String permission) {
        try {
            // 判断用户在Authing端是否是登录状态
            boolean status = authingUserDao.checkLoginStatusOnAuthing(userId);
            if (!status) {
                return "not logged in";
            }

            // token 页面请求权限验证
            if (userLoginToken != null && userLoginToken.required()) {
                String[] split = permission.split("->");
                boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
                if (!hasActionPer) {
                    return "has no permission";
                }
            }
        } catch (Exception e) {
            return "unauthorized";
        }
        return "success";
    }

    /**
     * 校验token
     *
     * @param headerToken header中带的token
     * @param token       cookie中解密的token
     * @param verifyToken 用于校验的token
     * @param userId      用户id
     * @param issuedAt    token创建时间
     * @param expiresAt   token过期时间
     * @param permission  用户权限信息
     * @return 校验结果
     */
    private String verifyToken(String headerToken, String token, String verifyToken,
                               String userId, Date issuedAt, Date expiresAt, String permission) {
        try {
            // header中的token和cookie中的token不一样
            if (!headerToken.equals(verifyToken)) {
                return "unauthorized";
            }

            // token 是否过期
            if (expiresAt.before(new Date())) {
                return "token expires";
            }

            // token 签名密码验证
            String password = permission + authingTokenBasePassword;
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(password)).build();
            jwtVerifier.verify(token);

            // 退出登录后token失效
            String redisKey = userId + issuedAt.toString();
            String beforeToken = (String) redisDao.get(redisKey);
            if (token.equalsIgnoreCase(beforeToken)) {
                return "unauthorized";
            }
        } catch (Exception e) {
            return "unauthorized";
        }
        return "success";
    }

    /**
     * 获取包含存token的cookie
     *
     * @param httpServletRequest request
     * @return cookie
     */
    private Cookie verifyCookie(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = httpServletRequest.getCookies();
        Cookie cookie = null;
        if (cookies != null) {
            // 获取cookie中的token
            Optional<Cookie> first = Arrays.stream(cookies).filter(c -> cookieTokenName.equals(c.getName())).findFirst();
            if (first.isPresent()) cookie = first.get();
        }
        return cookie;
    }

    /**
     * 校验domain
     *
     * @param httpServletRequest request
     * @return 是否可访问
     */
    private String verifyDomain(HttpServletRequest httpServletRequest) {
        String referer = httpServletRequest.getHeader("referer");
        String origin = httpServletRequest.getHeader("origin");
        String[] domains = allowDomains.split(";");

        boolean checkReferer = checkDomain(domains, referer);
        boolean checkOrigin = checkDomain(domains, origin);

        if (!checkReferer && !checkOrigin) {
            return "request not allowed";
        }
        return "success";
    }

    private boolean checkDomain(String[] domains, String input) {
        if (StringUtils.isBlank(input)) return true;
        int end = input.indexOf("/", 8);
        String substring = end == -1 ? input : input.substring(0, end);
        for (String domain : domains) {
            if (substring.endsWith(domain)) return true;
        }
        return false;
    }

    private void tokenError(HttpServletResponse httpServletResponse, Cookie tokenCookie, String message) throws IOException {
        HttpClientUtils.deleteCookie(httpServletResponse, tokenCookie, "/");
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }
}