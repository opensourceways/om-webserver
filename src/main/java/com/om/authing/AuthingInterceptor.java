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
import com.om.dao.RedisDao;
import com.om.modules.MessageCodeConfig;
import com.om.result.Constant;
import com.om.service.JwtTokenCreateService;
import com.om.utils.EncryptionService;
import com.om.utils.HttpClientUtils;
import com.om.utils.LogUtil;
import com.om.utils.ClientIPUtil;
import com.om.utils.RSAUtil;
import com.om.token.ClientSessionManager;
import com.om.token.ManageToken;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.util.CollectionUtils;
import org.springframework.util.DigestUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 拦截器类，用于进行身份验证拦截.
 */
public class AuthingInterceptor implements HandlerInterceptor {
    /**
     * 鉴权自身的接口.
     */
    private static final String LOCAL_VERIFY_TOKEN_URI = "/oneid/verify/token";

    /**
     * 登出接口.
     */
    private static final String LOGOUT_URI = "/oneid/logout";

    /**
     * 更新隐私接口.
     */
    private static final String BASEINFO_URI = "/oneid/update/baseInfo";

    /**
     * 用于与 Redis 数据库进行交互的 DAO.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * JWT Token 的创建服务.
     */
    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    /**
     * 应用程序的环境配置.
     */
    @Autowired
    private Environment env;

    /**
     * 注入三方客户端session管理类.
     */
    @Autowired
    private ClientSessionManager clientSessionManager;

    /**
     * 注入加密服务.
     */
    @Autowired
    private EncryptionService encryptionService;

    /**
     * Authing Token 的基础密码.
     */
    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    /**
     * RSA 加密算法使用的 Authing 私钥.
     */
    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;

    /**
     * 用于存储用户 Token 的 Cookie 名称.
     */
    @Value("${cookie.token.name}")
    private String cookieTokenName;

    /**
     * 用于存储验证 Token 的 Cookie 名称.
     */
    @Value("${cookie.verify.token.name}")
    private String verifyTokenName;

    /**
     * 可访问该应用程序的域名列表.
     */
    @Value("${cookie.token.domains}")
    private String allowDomains;

    /**
     * Cookie 安全性级别设置.
     */
    @Value("${cookie.token.secures}")
    private String cookieSecures;

    /**
     * OneID 隐私政策版本号.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

    /**
     * 三方鉴权接口.
     */
    @Value("${thirdService.verifyToken.url: }")
    private String thirdVerifyUrl;

    /**
     * 存储域名与安全性标志之间的映射关系.
     */
    private static HashMap<String, Boolean> domain2secure;

    /**
     * 日志记录器，用于记录身份验证拦截器的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingInterceptor.class);

    /**
     * Domain2secure实例赋值.
     *
     * @param domain2secure Domain2secure实例
     */
    public static void setDomain2secure(HashMap<String, Boolean> domain2secure) {
        AuthingInterceptor.domain2secure = domain2secure;
    }


    /**
     * 初始化方法，在对象创建后调用，用于初始化域名与安全性标志的映射关系.
     */
    @PostConstruct
    public void init() {
        setDomain2secure(HttpClientUtils.getConfigCookieInfo(allowDomains, cookieSecures));
    }

    /**
     * 预处理方法，在请求处理之前调用，用于进行预处理操作.
     *
     * @param httpServletRequest  HTTP 请求对象
     * @param httpServletResponse HTTP 响应对象
     * @param object              处理器
     * @return 返回布尔值表示是否继续处理请求
     * @throws Exception 可能抛出的异常
     */
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest,
                             HttpServletResponse httpServletResponse, Object object) throws Exception {
        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }

        // 检查有没有需要用户权限的注解，仅拦截AuthingToken和AuthingUserToken
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        if (!method.isAnnotationPresent(AuthingUserToken.class)) {
            return true;
        }
        AuthingUserToken authingUserToken = method.getAnnotation(AuthingUserToken.class);
        if (authingUserToken == null || !authingUserToken.required()) {
            return true;
        }

        if (!verifyThirdToken(httpServletRequest, httpServletResponse)) {
            tokenError(httpServletRequest, httpServletResponse, "unauthorized");
            return false;
        }

        // get if manageToken present
        ManageToken manageToken = method.getAnnotation(ManageToken.class);

        // 校验header中的token
        String headerJwtToken = httpServletRequest.getHeader("token");
        if (manageToken != null && manageToken.required()) {
            headerJwtToken = httpServletRequest.getHeader("user-token");
        }
        String headJwtTokenMd5 = verifyHeaderToken(headerJwtToken);
        String userIp = ClientIPUtil.getClientIpAddress(httpServletRequest);
        if (headJwtTokenMd5.equals("unauthorized") || headJwtTokenMd5.equals("token expires")) {
            tokenError(httpServletRequest, httpServletResponse, headJwtTokenMd5);
            if (headJwtTokenMd5.equals("token expires")) {
                DecodedJWT decode = JWT.decode(headerJwtToken);
                String user = decode.getAudience().get(0);
                LogUtil.createLogs(user, "token expire", "user", "The user's token expire",
                        userIp, "auto logout");
            }
            return false;
        }
        // 校验用户名
        if (!httpServletRequest.getRequestURI().equals(BASEINFO_URI)) {
            DecodedJWT jtd = JWT.decode(headerJwtToken);
            List<String> audiences = jtd.getAudience();
            if (CollectionUtils.isEmpty(audiences) || StringUtils.isEmpty(audiences.get(0))) {
                tokenError(httpServletRequest, httpServletResponse, "unset username");
                return false;
            }
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
        Date expiresAt;
        String permission;
        String verifyToken;
        String oneidPrivacyVersionAccept;
        Map<String, Claim> claims;
        try {
            DecodedJWT decode = JWT.decode(token);
            userId = decode.getAudience().get(0);
            expiresAt = decode.getExpiresAt();
            claims = decode.getClaims();
            String permissionTemp = claims.get("permission").asString();
            oneidPrivacyVersionAccept = claims.get("oneidPrivacyAccepted").asString();
            permission = new String(Base64.getDecoder()
                    .decode(permissionTemp
                            .getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
            verifyToken = claims.get("verifyToken").asString();
        } catch (JWTDecodeException j) {
            tokenError(httpServletRequest, httpServletResponse, "unauthorized");
            return false;
        }
        // 校验token
        String verifyTokenMsg = verifyToken(headJwtTokenMd5, token, verifyToken, expiresAt, permission, userIp, userId);
        if (!Constant.SUCCESS.equals(verifyTokenMsg)) {
            tokenError(httpServletRequest, httpServletResponse, verifyTokenMsg);
            return false;
        }

        // 是否接受隐私协议
        String url = httpServletRequest.getRequestURI();
        if (!isLoginNormal(verifyToken, userId)
                || (!"unused".equals(oneidPrivacyVersion) && !BASEINFO_URI.equals(url)
                && !oneidPrivacyVersion.equals(oneidPrivacyVersionAccept))) {
            if (!LOGOUT_URI.equals(url)) {
                tokenError(httpServletRequest, httpServletResponse, "unauthorized");
                return false;
            }
        }

        // skip refresh if manageToken present
        if (manageToken != null && manageToken.required()) {
            return true;
        }

        // 每次交互刷新token
        String refreshMsg = refreshToken(httpServletRequest, httpServletResponse, verifyToken, userId, claims);
        if (!Constant.SUCCESS.equals(refreshMsg)) {
            tokenError(httpServletRequest, httpServletResponse, refreshMsg);
            return false;
        }

        return true;
    }

    /**
     * 校验登录状态.
     *
     * @param verifyToken token
     * @param userId 用户id
     * @return 是否处于登录
     */
    private boolean isLoginNormal(String verifyToken, String userId) {
        String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(userId).toString();
        String tokenKey = Constant.ID_TOKEN_PREFIX + verifyToken;
        String idToken = (String) redisDao.get(tokenKey);
        try {
            idToken = encryptionService.privateDecrypt(idToken);
        } catch (Exception e) {
            LOGGER.error("idToken decrypt error {}", e.getMessage());
        }
        if (!redisDao.containListValue(loginKey, EncryptionService.getSha256Str(idToken))) {
            return false;
        }
        int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
        redisDao.setKeyExpire(loginKey, expireSeconds);
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
     * 校验header中的token.
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
            String md5Token = DigestUtils.md5DigestAsHex(headerToken.getBytes(StandardCharsets.UTF_8));
            if (!redisDao.exists("idToken_" + md5Token)) {
                return "token expires";
            }

            // token 签名密码验证
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(authingTokenBasePassword)).build();
            jwtVerifier.verify(headerToken);
            return md5Token;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return "unauthorized";
        }
    }

    /**
     * 校验token.
     *
     * @param headerToken header中带的token
     * @param token       cookie中解密的token
     * @param verifyToken 用于校验的token
     * @param expiresAt   token过期时间
     * @param permission  用户权限信息
     * @param userIp  用户IP
     * @param userId  用户ID
     * @return 校验结果
     */
    private String verifyToken(String headerToken, String token, String verifyToken,
                               Date expiresAt, String permission, String userIp, String userId) {
        try {
            // header中的token和cookie中的token不一样
            if (!headerToken.equals(verifyToken)) {
                return "unauthorized";
            }

            // token 是否过期
            if (expiresAt.before(new Date())) {
                LogUtil.createLogs(userId, "token expire", "user", "The user's token expire",
                        userIp, "auto logout");
                return "token expires";
            }

            // token 签名密码验证
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(permission + authingTokenBasePassword)).build();
            jwtVerifier.verify(token);
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException" + e.getMessage());
            return "unauthorized";
        } catch (Exception e) {
            return "unauthorized";
        }
        return "success";
    }

    /**
     * 获取包含存token的cookie.
     *
     * @param httpServletRequest request
     * @return cookie
     */
    private Cookie verifyCookie(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = httpServletRequest.getCookies();
        Cookie cookie = null;
        if (cookies != null) {
            // 获取cookie中的token
            Optional<Cookie> first = Arrays.stream(cookies)
                    .filter(c -> cookieTokenName.equals(c.getName())).findFirst();
            if (first.isPresent()) {
                cookie = first.get();
            }
        }
        return cookie;
    }

    /**
     * 校验domain.
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
        if (StringUtils.isBlank(input)) {
            return true;
        }
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
            if (substring.endsWith(domain)) {
                return true;
            }
        }
        return false;
    }

    private String refreshToken(HttpServletRequest request, HttpServletResponse response,
                                String verifyToken, String userId, Map<String, Claim> claimMap) {
        String oldTokenKey = Constant.ID_TOKEN_PREFIX + verifyToken;
        String idToken = (String) redisDao.get(oldTokenKey);
        String idTokenDecry = null;
        try {
            idTokenDecry = encryptionService.privateDecrypt(idToken);
        } catch (Exception e) {
            LOGGER.error("idToken encrypt error {}", e.getMessage());
        }

        if (idTokenDecry == null) {
            return Constant.TOKEN_EXPIRES;
        }
        // headToken刷新token
        String[] tokens = jwtTokenCreateService.refreshAuthingUserToken(request, idTokenDecry, userId, claimMap);

        // 刷新cookie
        int tokenExpire = Integer.parseInt(
                env.getProperty("authing.token.expire.seconds", Constant.DEFAULT_EXPIRE_SECOND));
        String maxAgeTemp = env.getProperty("authing.cookie.max.age");
        int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : tokenExpire;
        HttpClientUtils.setCookie(request, response, cookieTokenName, tokens[Constant.TOKEN_YG],
                true, maxAge, "/", domain2secure);
        HttpClientUtils.setCookie(request, response, verifyTokenName, tokens[Constant.TOKEN_UT],
                false, tokenExpire, "/", domain2secure);
        String newVerifyToken = DigestUtils.md5DigestAsHex(tokens[Constant.TOKEN_UT].getBytes(StandardCharsets.UTF_8));
        redisDao.set(Constant.ID_TOKEN_PREFIX + newVerifyToken, idToken, (long) tokenExpire);

        // 旧token失效,保持一个短时间的有效性
        long validityPeriod =
                Long.parseLong(env.getProperty("old.token.expire.seconds", Constant.DEFAULT_EXPIRE_SECOND));
        if (redisDao.expire(oldTokenKey) > validityPeriod) {
            redisDao.set(oldTokenKey, idToken, validityPeriod);
        }

        return Constant.SUCCESS;
    }

    private void tokenError(HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse,
                            String message) throws IOException {
        String refrer = httpServletRequest.getHeader("referer");
        List<String> childDomains = HttpClientUtils.extractSubdomains(refrer);
        Map<String, Boolean> cleanCookie = childDomains.stream().collect(Collectors.toMap(
                Function.identity(), // keyMapper，直接返回元素本身作为key
                item -> true, // valueMapper，每个key对应的value都是true
                (existing, replacement) -> existing
        ));
        cleanCookie.putAll(domain2secure);
        for (Map.Entry<String, Boolean> cookieEntry : cleanCookie.entrySet()) {
            HashMap<String, Boolean> clearMap = new HashMap<>();
            clearMap.put(cookieEntry.getKey(), cookieEntry.getValue());
            HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, cookieTokenName,
                    null, true, 0, "/", clearMap);
            HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, verifyTokenName,
                    null, false, 0, "/", clearMap);
        }
        clientSessionManager.deleteCookieInConfig(httpServletResponse);

        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    /**
     * 三方鉴权.
     *
     * @param request 请求体
     * @param response 响应体
     * @return 是否成功
     */
    private boolean verifyThirdToken(HttpServletRequest request, HttpServletResponse response) {
        if (StringUtils.isBlank(thirdVerifyUrl)) {
            return true;
        }
        String uri = request.getRequestURI();
        if (LOCAL_VERIFY_TOKEN_URI.equals(uri)) {
            return true;
        }
        try {
            String headerToken = request.getHeader("Csrf-Token");
            String cookie = request.getHeader("Cookie");
            HttpResponse<JsonNode> restResponse = Unirest.get(thirdVerifyUrl)
                    .header("Content-Type", "application/json")
                    .header("Csrf-Token", headerToken)
                    .header("Cookie", cookie).asJson();
            if (restResponse.getStatus() == 401) {
                return false;
            }
            if (restResponse.getStatus() == 200) {
                List<String> setCookies = restResponse.getHeaders().get("Set-Cookie");
                if (setCookies != null) {
                    for (String setCookie : setCookies) {
                        response.addHeader("Set-Cookie", setCookie);
                    }
                }
            }
        } catch (UnirestException e) {
            LOGGER.error("get third service token verify failed {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.error("get third service token verify failed {}", e.getMessage());
        }

        return true;
    }
}
