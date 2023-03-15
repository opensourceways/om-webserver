/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.authing;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Service.JwtTokenCreateService;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.util.DigestUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

public class AuthingInterceptor implements HandlerInterceptor {
    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    @Autowired
    private Environment env;

    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;

    @Value("${cookie.token.name}")
    private String cookieTokenName;

    @Value("${cookie.verify.token.name}")
    private String verifyTokenName;

    @Value("${cookie.token.domains}")
    private String allowDomains;

    @Value("${cookie.token.secures}")
    private String cookieSecures;

    private static HashMap<String, Boolean> domain2secure;

    @PostConstruct
    public void init() {
        domain2secure = HttpClientUtils.getConfigCookieInfo(allowDomains, cookieSecures);
    }

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }

        // 检查有没有需要用户权限的注解，仅拦截AuthingToken和AuthingUserToken
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        if (!method.isAnnotationPresent(AuthingToken.class) && !method.isAnnotationPresent(AuthingUserToken.class)
                && !method.isAnnotationPresent(CompanyToken.class)) {
            return true;
        }
        AuthingToken userLoginToken = method.getAnnotation(AuthingToken.class);
        AuthingUserToken authingUserToken = method.getAnnotation(AuthingUserToken.class);
        SigToken sigToken = method.getAnnotation(SigToken.class);
        CompanyToken companyToken = method.getAnnotation(CompanyToken.class);
        if ((userLoginToken == null || !userLoginToken.required())
                && (authingUserToken == null || !authingUserToken.required())
                && (sigToken == null || !sigToken.required())
                && (companyToken == null || !companyToken.required())) {
            return true;
        }

        // 校验header中的token
        String headerJwtToken = httpServletRequest.getHeader("token");
        String headJwtTokenMd5 = verifyHeaderToken(headerJwtToken);
        if (headJwtTokenMd5.equals("unauthorized") || headJwtTokenMd5.equals("token expires")) {
            tokenError(httpServletRequest, httpServletResponse, headJwtTokenMd5);
            return false;
        }

        // 校验domain
        String verifyDomainMsg = verifyDomain(httpServletRequest);
        if (!verifyDomainMsg.equals("success")) {
            tokenError(httpServletRequest, httpServletResponse, verifyDomainMsg);
            return false;
        }

        // 校验cookie
        Cookie tokenCookie = verifyCookie(httpServletRequest);
        if (tokenCookie == null) {
            tokenError(httpServletRequest, httpServletResponse, "unauthorized");
            return false;
        }

        // 解密cookie中加密的token
        String token = tokenCookie.getValue();
        try {
            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
            token = RSAUtil.privateDecrypt(token, privateKey);
        } catch (Exception e) {
            tokenError(httpServletRequest, httpServletResponse, "unauthorized");
            return false;
        }

        // 解析token
        String userId;
        Date issuedAt;
        Date expiresAt;
        String permission;
        String verifyToken;
        Map<String, Claim> claims;
        try {
            DecodedJWT decode = JWT.decode(token);
            userId = decode.getAudience().get(0);
            issuedAt = decode.getIssuedAt();
            expiresAt = decode.getExpiresAt();
            claims = decode.getClaims();
            String permissionTemp = claims.get("permission").asString();
            permission = new String(Base64.getDecoder().decode(permissionTemp.getBytes()));
            verifyToken = claims.get("verifyToken").asString();
        } catch (JWTDecodeException j) {
            tokenError(httpServletRequest, httpServletResponse, "unauthorized");
            return false;
        }

        // 校验token
        String verifyTokenMsg = verifyToken(headJwtTokenMd5, token, verifyToken, userId,
                issuedAt, expiresAt, permission);

        // 如果token过期，使用headToken刷新token
        String newHeaderJwtToken = headerJwtToken;
        String idToken = (String) redisDao.get("idToken_" + headJwtTokenMd5);
        if (verifyTokenMsg.equals("token expires") && idToken != null) {
            if (redisDao.get(headJwtTokenMd5) == null) {
                newHeaderJwtToken = refreshToken(httpServletRequest, httpServletResponse,
                        verifyToken, userId, claims);
            }
            verifyTokenMsg = "success";
        }

        if (!verifyTokenMsg.equals("success")) {
            tokenError(httpServletRequest, httpServletResponse, verifyTokenMsg);
            return false;
        }

        // 每次调用刷新headerToken的过期时间，保证有交付保持登录
        int tokenExpire = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "1800"));
        String newVerifyToken = DigestUtils.md5DigestAsHex(newHeaderJwtToken.getBytes());
        redisDao.set("idToken_" + newVerifyToken, idToken, (long) tokenExpire);
        HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, verifyTokenName,
                newHeaderJwtToken, false, tokenExpire, "/", domain2secure);

        // 校验sig权限
        if (sigToken != null && sigToken.required()) {
            String verifyUserMsg = verifyUser(sigToken, userId, permission);
            if (!verifyUserMsg.equals("success")) {
                tokenError(httpServletRequest, httpServletResponse, verifyUserMsg);
                return false;
            }
        }
        // 校验company权限
        if (companyToken != null && companyToken.required()) {
            String verifyCompanyPerMsg = verifyCompanyPer(companyToken, userId);
            if (!verifyCompanyPerMsg.equals("success")) {
                tokenError(httpServletRequest, httpServletResponse, verifyCompanyPerMsg);
                return false;
            }
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
     * 校验header中的token
     *
     * @param headerToken header中的token
     * @return 校验正确返回token的MD5值
     */
    private String verifyHeaderToken(String headerToken) {
        try {
            if (StringUtils.isBlank(headerToken)) {
                return "unauthorized";
            }

            // 服务端校验headerToken是否有效
            String md5Token = DigestUtils.md5DigestAsHex(headerToken.getBytes());
            if (!redisDao.exists("idToken_" + md5Token)) {
                return "token expires";
            }

            // token 签名密码验证
            String password = authingTokenBasePassword;
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(password)).build();
            jwtVerifier.verify(headerToken);
            return md5Token;
        } catch (Exception e) {
            e.printStackTrace();
            return "unauthorized";
        }
    }

    /**
     * 校验用户（登录状态，操作权限）
     *
     * @param sigToken   SigToken（仅带有该注解的接口需要校验操作权限）
     * @param userId     用户id
     * @param permission 需要的操作权限
     * @return 校验结果
     */
    private String verifyUser(SigToken sigToken, String userId, String permission) {
        try {
            // token 页面请求权限验证
            if (sigToken != null && sigToken.required()) {
                String[] split = permission.split("->");
                boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
                if (!hasActionPer) {
                    return "has no permission";
                }
            }
        } catch (Exception e) {
            return "has no permission";
        }
        return "success";
    }

    private String verifyCompanyPer(CompanyToken companyToken, String userId) {
        try {
            if (companyToken != null && companyToken.required()) {
                ArrayList<String> pers =
                        authingUserDao.getUserPermission(userId, env.getProperty("openeuler.groupCode"));
                for (String per : pers) {
                    String[] perList = per.split(":");
                    if (perList.length > 1
                            && perList[1].equalsIgnoreCase(env.getProperty("openeuler.companyAction"))) {
                        return "success";
                    }
                }
            }
        } catch (Exception e) {
            return "has no permission";
        }
        return "has no permission";
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
            return "unauthorized";
        }
        return "success";
    }

    private boolean checkDomain(String[] domains, String input) {
        if (StringUtils.isBlank(input)) return true;
        int fromIndex;
        int endIndex;
        if (input.startsWith("http://")) {
            fromIndex = 7;
            endIndex = input.indexOf(":", fromIndex);
        } else {
            fromIndex = 8;
            endIndex = input.indexOf("/", fromIndex);
            endIndex = endIndex == -1 ? input.length() : endIndex;
        }
        String substring = input.substring(0, endIndex);
        for (String domain : domains) {
            if (substring.endsWith(domain)) return true;
        }
        return false;
    }

    private String refreshToken(HttpServletRequest request, HttpServletResponse response,
                                String verifyToken, String userId, Map<String, Claim> claimMap) {
        // headToken刷新token
        String[] tokens = jwtTokenCreateService.refreshAuthingUserToken(request, response, userId, claimMap);

        // 刷新cookie
        int tokenExpire = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "1800"));
        String maxAgeTemp = env.getProperty("authing.cookie.max.age");
        int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : tokenExpire;
        HttpClientUtils.setCookie(request, response, cookieTokenName, tokens[0],
                true, maxAge, "/", domain2secure);

        // 旧token失效
        redisDao.remove("idToken_" + verifyToken);
        return tokens[1];
    }

    private void tokenError(HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse,
                            String message) throws IOException {
        HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, cookieTokenName,
                null, true, 0, "/", domain2secure);

        HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, verifyTokenName,
                null, false, 0, "/", domain2secure);

        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }
}