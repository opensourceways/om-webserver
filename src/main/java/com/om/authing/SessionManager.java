/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.authing;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Dao.RedisDao;
import com.om.Result.Constant;
import com.om.Service.JwtTokenCreateService;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * sessiong管理器
 */
@Service
public class SessionManager {
    /**
     * 日志记录器，用于记录身份验证拦截器的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SessionManager.class);

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
     * OneID 隐私政策版本号.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

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
     * 存储域名与安全性标志之间的映射关系.
     */
    private static HashMap<String, Boolean> domain2secure;

    /**
     * Domain2secure实例赋值.
     *
     * @param domain2secure Domain2secure实例
     */
    public static void setDomain2secure(HashMap<String, Boolean> domain2secure) {
        SessionManager.domain2secure = domain2secure;
    }

    /**
     * 初始化方法，在对象创建后调用，用于初始化域名与安全性标志的映射关系.
     */
    @PostConstruct
    public void init() {
        setDomain2secure(HttpClientUtils.getConfigCookieInfo(allowDomains, cookieSecures));
    }

    /**
     * 检查session会话
     *
     * @param httpServletRequest 请求体
     * @param httpServletResponse 响应体
     * @param isRefreshCookie 是否刷新cookie
     * @param isManageToken 是否是管理面接口
     * @return 会话是否OK
     */
    public String checkSession(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                boolean isRefreshCookie, boolean isManageToken) {
        // 校验header中的token
        String headerJwtToken = httpServletRequest.getHeader("token");
        if (!isRefreshCookie && isManageToken) {
            headerJwtToken = httpServletRequest.getHeader("user-token");
        }
        String headJwtTokenMd5 = verifyHeaderToken(headerJwtToken);
        if (headJwtTokenMd5.equals("unauthorized") || headJwtTokenMd5.equals("token expires")) {
            return headJwtTokenMd5;
        }

        // 校验domain
        String verifyDomainMsg = verifyDomain(httpServletRequest);
        if (!verifyDomainMsg.equals("success")) {
            return verifyDomainMsg;
        }

        // 校验cookie
        Cookie tokenCookie = verifyCookie(httpServletRequest);
        if (tokenCookie == null) {
            return "unauthorized";
        }

        // 解密cookie中加密的token
        String token = tokenCookie.getValue();
        try {
            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
            token = RSAUtil.privateDecrypt(token, privateKey);
        } catch (Exception e) {
            return "unauthorized";
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
            return "unauthorized";
        }

        // 是否接受隐私协议
        String url = httpServletRequest.getRequestURI();
        if (!"unused".equals(oneidPrivacyVersion) && !"/oneid/update/baseInfo".equals(url)
                && !oneidPrivacyVersion.equals(oneidPrivacyVersionAccept)) {
            return "Not accept privacy policy and terms of service.";
        }

        // 校验token
        String verifyTokenMsg = verifyToken(headJwtTokenMd5, token, verifyToken, expiresAt, permission);
        if (!Constant.SUCCESS.equals(verifyTokenMsg)) {
            return verifyTokenMsg;
        }
        // 校验登录状态
        if (!isLoginNormal(verifyToken, userId)) {
            return "unauthorized";
        }

        // skip refresh if manageToken present
        if (!isRefreshCookie) {
            return Constant.SUCCESS;
        }

        // 每次交互刷新token
        String refreshMsg = refreshToken(httpServletRequest, httpServletResponse, verifyToken, userId, claims);
        if (!Constant.SUCCESS.equals(refreshMsg)) {
            return refreshMsg;
        }
        return Constant.SUCCESS;
    }

    /**
     * 鉴权失败，清理token
     *
     * @param httpServletRequest 请求体
     * @param httpServletResponse 响应体
     * @param message 错误信息
     * @throws IOException 异常信息
     */
    public void tokenError(HttpServletRequest httpServletRequest,
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
        HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, cookieTokenName,
                null, true, 0, "/", (HashMap<String, Boolean>) cleanCookie);

        HttpClientUtils.setCookie(httpServletRequest, httpServletResponse, verifyTokenName,
                null, false, 0, "/", (HashMap<String, Boolean>) cleanCookie);

        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    /**
     * 校验登录状态.
     *
     * @param verifyToken token
     * @param userId      用户id
     * @return 是否处于登录
     */
    private boolean isLoginNormal(String verifyToken, String userId) {
        String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(userId).toString();
        String tokenKey = Constant.ID_TOKEN_PREFIX + verifyToken;
        String idToken = (String) redisDao.get(tokenKey);
        if (!redisDao.containListValue(loginKey, idToken)) {
            return false;
        }
        int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
        redisDao.setKeyExpire(loginKey, expireSeconds);
        return true;
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
            LOGGER.error("Internal Server Error {}", e.getMessage());
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
     * @return 校验结果
     */
    private String verifyToken(String headerToken, String token, String verifyToken,
                               Date expiresAt, String permission) {
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
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(permission + authingTokenBasePassword)).build();
            jwtVerifier.verify(token);
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException {}", e.getMessage());
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
    public Cookie verifyCookie(HttpServletRequest httpServletRequest) {
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
        if (idToken == null) {
            return Constant.TOKEN_EXPIRES;
        }
        // headToken刷新token
        String[] tokens = jwtTokenCreateService.refreshAuthingUserToken(request, idToken, userId, claimMap);

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
}