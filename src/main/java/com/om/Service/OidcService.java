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

package com.om.Service;

import cn.authing.core.types.Application;
import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Utils.AuthingUtil;
import com.om.Utils.CodeUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.util.HtmlUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * oidc服务.
 */
@Service
public class OidcService {
    /**
     * 静态变量: LOGGER - 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcService.class);

    /**
     * 静态常量: OIDCISSUER - OneID发行者常量.
     */
    private static final String OIDCISSUER = "ONEID";

    /**
     * ObjectMapper实例.
     */
    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * CodeUtil实例.
     */
    private CodeUtil codeUtil = new CodeUtil();

    /**
     * 使用 @Autowired 注解注入环境变量.
     */
    @Autowired
    private Environment env;

    /**
     * authing服务.
     */
    @Autowired
    private AuthingService authingService;

    /**
     * 使用 @Autowired 注解注入 AuthingUserDao.
     */
    @Autowired
    private AuthingUserDao authingUserDao;

    /**
     * 使用 @Autowired 注解注入 RedisDao.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 使用 @Autowired 注解注入 QueryDao.
     */
    @Autowired
    private QueryDao queryDao;

    /**
     * 使用 @Autowired 注解注入 JwtTokenCreateService.
     */
    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    /**
     * 使用 @Autowired 注解注入authingUtil.
     */
    @Autowired
    private AuthingUtil authingUtil;

    /**
     * 在线用户管理.
     */
    @Autowired
    private OnlineUserManager onlineUserManager;

    /**
     * 静态变量: 实例社区信息.
     */
    @Value("${community: }")
    private String instanceCommunity;

    /**
     * 静态变量: OIDC作用域映射（Authing）.
     */
    private HashMap<String, String> oidcScopeAuthingMapping;

    /**
     * 静态变量: OIDC作用域映射（其他）.
     */
    private HashMap<String, String[]> oidcScopeOthers;

    /**
     * 初始化方法.
     */
    @PostConstruct
    public void init() {
        oidcScopeAuthingMapping = getOidcScopeAuthingMapping();
        oidcScopeOthers = getOidcScopesOther();
    }

    /**
     * OIDC授权方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity oidcAuthorize(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        try {
            Map<String, String[]> parameterMap = servletRequest.getParameterMap();
            String clientId = parameterMap.getOrDefault("client_id", new String[]{""})[0];
            String responseType = parameterMap.getOrDefault("response_type", new String[]{""})[0];
            String redirectUri = parameterMap.getOrDefault("redirect_uri", new String[]{""})[0];
            String scope = parameterMap.getOrDefault("scope", new String[]{""})[0];
            String state = parameterMap.getOrDefault("state", new String[]{""})[0];
            String entity = parameterMap.getOrDefault("entity", new String[]{""})[0];
            String complementation = parameterMap.getOrDefault("complementation", new String[]{""})[0];
            String lang = parameterMap.getOrDefault("lang", new String[]{""})[0];
            // responseType校验
            if (!responseType.equals("code")) {
                return resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);
            }
            // app回调地址校验
            ResponseEntity responseEntity = authingService.appVerify(clientId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200) {
                return resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);
            }
            // 若缺少state,后端自动生成
            state = StringUtils.isNotBlank(state) ? state : UUID.randomUUID().toString().replaceAll("-", "");
            // scope默认<openid profile>
            scope = StringUtils.isBlank(scope) ? "openid profile" : scope;
            // 重定向到登录页
            String loginPage = env.getProperty("oidc.login.page");
            if ("register".equals(entity)) {
                loginPage = env.getProperty("oidc.register.page");
            }
            String complParam = StringUtils.isBlank(complementation)
                    ? "" : String.format("&complementation=%s", complementation);
            String langParam = StringUtils.isBlank(lang) ? "" : String.format("&lang=%s", lang);
            redirectUri = URLEncoder.encode(redirectUri, "UTF-8");
            String loginPageRedirect = String.format(
                    "%s?client_id=%s&scope=%s&redirect_uri=%s&response_mode=query&state=%s%s%s",
                    loginPage, clientId, scope, redirectUri, state, complParam, langParam);
            servletResponse.sendRedirect(loginPageRedirect);
            return resultOidc(HttpStatus.OK, "OK", loginPageRedirect);
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    /**
     * OIDC令牌方法.
     *
     * @param servletRequest HTTP请求对象
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity oidcToken(HttpServletRequest servletRequest) {
        try {
            Map<String, String[]> parameterMap = servletRequest.getParameterMap();
            String grantType = parameterMap.getOrDefault("grant_type", new String[]{""})[0];
            if (grantType.equals("authorization_code")) {
                String appId;
                String appSecret;
                if (parameterMap.containsKey("client_id") && parameterMap.containsKey("client_secret")) {
                    appId = parameterMap.getOrDefault("client_id", new String[]{""})[0];
                    appSecret = parameterMap.getOrDefault("client_secret", new String[]{""})[0];
                } else {
                    String header = servletRequest.getHeader("Authorization");
                    byte[] authorization = Base64.getDecoder().decode(header.replace("Basic ", ""));
                    String[] split = new String(authorization, StandardCharsets.UTF_8).split(":");
                    appId = split[0];
                    appSecret = split[1];
                }
                String redirectUri = parameterMap.getOrDefault("redirect_uri", new String[]{""})[0];
                String code = parameterMap.getOrDefault("code", new String[]{""})[0];
                String logoutUrl = parameterMap.getOrDefault("logout_uri", new String[]{""})[0];
                return getOidcTokenByCode(appId, appSecret, code, redirectUri, logoutUrl);
            } else if (grantType.equals("password")) {
                String appId;
                String appSecret;
                if (parameterMap.containsKey("client_id") && parameterMap.containsKey("client_secret")) {
                    appId = parameterMap.getOrDefault("client_id", new String[]{""})[0];
                    appSecret = parameterMap.getOrDefault("client_secret", new String[]{""})[0];
                } else {
                    String header = servletRequest.getHeader("Authorization");
                    byte[] authorization = Base64.getDecoder().decode(header.replace("Basic ", ""));
                    String[] split = new String(authorization, StandardCharsets.UTF_8).split(":");
                    appId = split[0];
                    appSecret = split[1];
                }
                String redirectUri = parameterMap.getOrDefault("redirect_uri", new String[]{""})[0];
                String account = parameterMap.getOrDefault("account", new String[]{""})[0];
                String password = parameterMap.getOrDefault("password", new String[]{""})[0];
                String scope = parameterMap.getOrDefault("scope", new String[]{""})[0];
                return getOidcTokenByPassword(appId, appSecret, account, password, redirectUri, scope);
            } else if (grantType.equals("refresh_token")) {
                String refreshToken = parameterMap.getOrDefault("refresh_token", new String[]{""})[0];
                return oidcRefreshToken(refreshToken);
            } else {
                return resultOidc(HttpStatus.BAD_REQUEST,
                        "grant_type must be authorization_code or refresh_token", null);
            }
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
            redisDao.remove("code");
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    /**
     * 解析oidc支持的scope.
     *
     * @return scope map
     */
    private HashMap<String, String> getOidcScopeAuthingMapping() {
        String[] mappings = env.getProperty("oidc.scope.authing.mapping", "").split(",");
        HashMap<String, String> authingMapping = new HashMap<>();
        for (String mapping : mappings) {
            if (StringUtils.isBlank(mapping)) {
                continue;
            }
            String[] split = mapping.split(":");
            authingMapping.put(split[0], split[1]);
        }
        return authingMapping;
    }

    /**
     * 解析oidc支持的scope.
     *
     * @return 其他的scope map
     */
    private HashMap<String, String[]> getOidcScopesOther() {
        String[] others = env.getProperty("oidc.scope.other", "").split(";");
        HashMap<String, String[]> otherMap = new HashMap<>();
        for (String other : others) {
            if (StringUtils.isBlank(other)) {
                continue;
            }
            String[] split = other.split("->");
            otherMap.put(split[0], split[1].split(","));
        }
        return otherMap;
    }

    /**
     * OIDC认证方法.
     *
     * @param token        认证令牌
     * @param appId        应用ID
     * @param redirectUri  重定向URI
     * @param responseType 响应类型
     * @param state        状态
     * @param scope        范围
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity oidcAuth(String token, String appId,
                                   String redirectUri, String responseType, String state, String scope) {
        try {
            // responseType校验
            if (!responseType.equals("code")) {
                return resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);
            }
            // scope校验
            List<String> scopes = Arrays.asList(scope.split(" "));
            if (!scopes.contains("openid") || !scopes.contains("profile")) {
                return resultOidc(HttpStatus.NOT_FOUND, "scope must contain <openid profile>", null);
            }
            redirectUri = URLDecoder.decode(redirectUri, "UTF-8");
            // app回调地址校验
            ResponseEntity responseEntity = authingService.appVerify(appId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200) {
                return resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);
            }
            // 获取登录用户ID
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            String headToken = decode.getClaim("verifyToken").asString();
            String idToken = (String) redisDao.get("idToken_" + headToken);
            List<String> accessibleApps = authingUserDao.userAccessibleApps(userId);
            if (!accessibleApps.contains(appId)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "No permission to login the application", null);
            }
            // 生成code和state
            String code = codeUtil.randomStrBuilder(32);
            state = StringUtils.isNotBlank(state) ? state : UUID.randomUUID().toString().replaceAll("-", "");
            // 生成access_token和refresh_token
            scope = StringUtils.isBlank(scope) ? "openid profile" : scope;
            long codeExpire = Long.parseLong(env.getProperty("oidc.code.expire", "60"));
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, accessTokenExpire, null);
            String refreshToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, refreshTokenExpire, null);
            // 缓存 code
            HashMap<String, String> codeMap = new HashMap<>();
            codeMap.put("accessToken", accessToken);
            codeMap.put("refreshToken", refreshToken);
            codeMap.put("idToken", idToken);
            codeMap.put("appId", appId);
            codeMap.put("redirectUri", redirectUri);
            codeMap.put("scope", scope);
            codeMap.put("userId", userId);
            String codeMapStr = "oidcCode:" + objectMapper.writeValueAsString(codeMap);
            redisDao.set(code, codeMapStr, codeExpire);
            // 缓存 oidcToken
            HashMap<String, String> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessToken);
            userTokenMap.put("refresh_token", refreshToken);
            userTokenMap.put("idToken", idToken);
            userTokenMap.put("scope", scope);
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes(StandardCharsets.UTF_8)),
                    userTokenMapStr,
                    refreshTokenExpire);
            URIBuilder uriBuilder = new URIBuilder(redirectUri);
            uriBuilder.setParameter("code", code);
            uriBuilder.setParameter("state", state);
            String res = uriBuilder.build().toString();
            return resultOidc(HttpStatus.OK, "OK", res);
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException." + e.getMessage());
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        } catch (Exception ex) {
            LOGGER.error("Internal Server Error {}", ex.getMessage());
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    /**
     * 根据访问令牌获取用户信息的方法.
     *
     * @param servletRequest HTTP请求对象
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity userByAccessToken(HttpServletRequest servletRequest) {
        try {
            String authorization = servletRequest.getHeader("Authorization");
            if (StringUtils.isBlank(authorization)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            }
            String accessToken = authorization.replace("Bearer ", "");
            // 解析access_token
            String token = authingUtil.rsaDecryptToken(accessToken);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();
            // token是否被刷新了或者已经过期
            Object refreshedToken = redisDao.get(DigestUtils
                    .md5DigestAsHex(accessToken.getBytes(StandardCharsets.UTF_8)));
            if (refreshedToken != null || expiresAt.before(new Date())) {
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            }
            // 获取用户
            JSONObject userObj = authingUserDao.getUserById(userId);
            // 根据scope获取用户信息 oidcScopeAuthingMapping(临时,字段映射)
            HashMap<String, Object> userData = new HashMap<>();
            HashMap<String, Object> addressMap = new HashMap<>();
            // 1、默认字段
            String[] profiles = env.getProperty("oidc.scope.profile", "").split(",");
            for (String profile : profiles) {
                String profileTemp = oidcScopeAuthingMapping.getOrDefault(profile, profile);
                Object value = authingUtil.jsonObjObjectValue(userObj, profileTemp);
                if ("updated_at".equals(profile) && value != null) {
                    DateTimeFormatter df = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    value = LocalDateTime.parse(value.toString(), df).toInstant(ZoneOffset.UTC).toEpochMilli();
                }
                userData.put(profile, value);
            }
            // 2、指定字段
            String[] scopes = decode.getClaim("scope").asString().split(" ");
            for (String scope : scopes) {
                if (scope.equals("openid") || scope.equals("profile")) {
                    continue;
                }
                // 三方登录字段
                if (scope.equals("identities")) {
                    ArrayList<Map<String, Object>> identities = authingUtil.authingUserIdentity(userObj);
                    userData.put("identities", identities);
                    continue;
                }
                // 用户SIG组信息
                if (scope.equals("groups")) {
                    // Gitee Name
                    String giteeLogin = getGiteeLoginFromAuthing(userId);
                    String userSigInfo = queryDao.queryUserOwnertype("openeuler", giteeLogin);
                    ArrayList<String> groups = getUserRelatedSigs(userSigInfo);
                    userData.put("groups", groups);
                    continue;
                }
                String[] claims = oidcScopeOthers.getOrDefault(scope, new String[]{scope});
                for (String claim : claims) {
                    String profileTemp = oidcScopeAuthingMapping.getOrDefault(claim, claim);
                    Object value = authingUtil.jsonObjObjectValue(userObj, profileTemp);
                    // auto generate email if not exist
                    if ("openeuler".equals(instanceCommunity) && "email".equals(claim) && value == null) {
                        String prefix = authingUtil.jsonObjStringValue(userObj, "username");
                        if (StringUtils.isBlank(prefix)) {
                            prefix = authingUtil.jsonObjStringValue(userObj, "phone");
                        }
                        value = authingService.genPredefinedEmail(userId, prefix);
                    }
                    if (scope.equals("address")) {
                        addressMap.put(claim, value);
                    } else {
                        userData.put(claim, value);
                    }
                }
                if (scope.equals("address")) {
                    userData.put(scope, addressMap);
                }
            }
            HashMap<String, Object> res = new HashMap<>();
            res.put("code", 200);
            res.put("data", userData);
            res.put("msg", "OK");
            res.putAll(userData);
            ResponseEntity<HashMap<String, Object>> responseEntity = new ResponseEntity<>(res, HttpStatus.OK);
            return responseEntity;
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    private String getGiteeLoginFromAuthing(String userId) {
        String giteeLogin = "";
        if (StringUtils.isBlank(userId)) {
            return giteeLogin;
        }
        try {
            JSONArray identities = authingUserDao.getUserById(userId).getJSONArray("identities");
            for (Object identity : identities) {
                JSONObject identityObj = (JSONObject) identity;
                String originConnId = identityObj.getJSONArray("originConnIds").get(0).toString();
                if (!originConnId.equals(env.getProperty("enterprise.connId.gitee"))) {
                    continue;
                }
                giteeLogin = identityObj
                        .getJSONObject("userInfoInIdp").getJSONObject("customData").getString("giteeLogin");
            }
        } catch (Exception e) {
            LOGGER.error("Fail to get gitee name. " + e.getMessage());
        }
        return giteeLogin;
    }

    private ArrayList<String> getUserRelatedSigs(String userSigInfo) {
        ArrayList<String> userRelatedSigs = new ArrayList<>();
        try {
            JsonNode body = objectMapper.readTree(userSigInfo);
            if (body.get("data") != null) {
                for (JsonNode sigInfo : body.get("data")) {
                    userRelatedSigs.add(sigInfo.get("sig").asText());
                }
            }
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return userRelatedSigs;
    }

    private ResponseEntity getOidcTokenByPassword(String appId, String appSecret, String account,
                                                  String password, String redirectUri, String scope) {
        try {
            // 参数校验
            if (StringUtils.isBlank(appId) || StringUtils.isBlank(appSecret)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "not found the app", null);
            }
            if (StringUtils.isBlank(password) || StringUtils.isBlank(redirectUri)) {
                return resultOidc(HttpStatus.BAD_REQUEST,
                        "when grant_type is password, parameters must contain password、redirectUri", null);
            }
            scope = StringUtils.isBlank(scope) ? "openid profile" : scope;
            // app密码校验
            Application app = authingUserDao.getAppById(appId);
            if (app == null || !app.getSecret().equals(appSecret)) {
                return resultOidc(HttpStatus.NOT_FOUND, "app invalid or secret error", null);
            }
            // 限制一分钟登录失败次数
            String loginErrorCountKey = account + "loginCount";
            Object v = redisDao.get(loginErrorCountKey);
            int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
            if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.limit.count", "6"))) {
                return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, null);
            }
            // 用户密码校验
            Object loginRes = authingService.login(appId, account, null, password);
            // 获取用户信息
            String userId;
            String idToken;
            if (loginRes instanceof JSONObject userObj) {
                idToken = userObj.getString("id_token");
                userId = JWT.decode(idToken).getSubject();
            } else {
                long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
                loginErrorCount += 1;
                redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
                return authingService.result(HttpStatus.BAD_REQUEST, null, (String) loginRes, null);
            }
            //登录成功解除登录失败次数限制
            redisDao.remove(loginErrorCountKey);
            // 生成access_token和refresh_token
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, accessTokenExpire, null);
            String refreshToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, refreshTokenExpire, null);
            long expire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            HashMap<String, Object> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);
            tokens.put("scope", scope);
            tokens.put("expires_in", expire);
            tokens.put("token_type", "Bearer");
            List<String> scopes = Arrays.asList(scope.split(" "));
            if (scopes.contains("offline_access")) {
                tokens.put("refresh_token", refreshToken);
            }
            if (scopes.contains("id_token")) {
                tokens.put("idToken", idToken);
            }
            // 缓存 oidcToken
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(tokens);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes(StandardCharsets.UTF_8)),
                    userTokenMapStr, refreshTokenExpire);
            ResponseEntity<HashMap<String, Object>> responseEntity =
                    new ResponseEntity<>(JSON.parseObject(
                            HtmlUtils.htmlUnescape(JSON.toJSONString(tokens)), HashMap.class), HttpStatus.OK);
            return responseEntity;
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    private ResponseEntity oidcRefreshToken(String refreshToken) {
        try {
            if (StringUtils.isBlank(refreshToken)) {
                return resultOidc(HttpStatus.BAD_REQUEST,
                        "when grant_type is authorization_code,parameters must contain refresh_token", null);
            }
            // 解析refresh_token
            DecodedJWT decode = JWT.decode(authingUtil.rsaDecryptToken(refreshToken));
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();
            // tokens校验
            String refreshTokenKey = DigestUtils.md5DigestAsHex(refreshToken.getBytes(StandardCharsets.UTF_8));
            String tokenStr = (String) redisDao.get(refreshTokenKey);
            if (StringUtils.isBlank(tokenStr)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            }
            // refresh_token是否过期
            if (expiresAt.before(new Date())) {
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            }
            JsonNode jsonNode = objectMapper.readTree(
                    tokenStr.replace("oidcTokens:", ""));
            String scope = jsonNode.get("scope").asText();
            String accessToken = jsonNode.get("access_token").asText();
            // 生成新的accessToken和refreshToken
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessTokenNew = jwtTokenCreateService.oidcToken(userId, OIDCISSUER,
                    scope, accessTokenExpire, null);
            String refreshTokenNew = jwtTokenCreateService.oidcToken(userId, OIDCISSUER,
                    scope, refreshTokenExpire, expiresAt);
            // 缓存新的accessToken和refreshToken
            long expire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            HashMap<String, Object> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessTokenNew);
            userTokenMap.put("refresh_token", refreshTokenNew);
            userTokenMap.put("scope", scope);
            userTokenMap.put("expires_in", expire);
            List<String> scopes = Arrays.asList(scope.split(" "));
            if (scopes.contains("id_token")) {
                userTokenMap.put("idToken", jsonNode.get("idToken").asText());
            }
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshTokenNew.getBytes(StandardCharsets.UTF_8)),
                    userTokenMapStr, refreshTokenExpire);
            // 移除以前的refresh_token，并将之前的access_token失效
            redisDao.remove(refreshTokenKey);
            redisDao.set(DigestUtils.md5DigestAsHex(accessToken.getBytes(StandardCharsets.UTF_8)),
                    accessToken, accessTokenExpire);
            ResponseEntity<HashMap<String, Object>> responseEntity =
                    new ResponseEntity<>(JSON.parseObject(
                            HtmlUtils.htmlUnescape(JSON.toJSONString(userTokenMap)), HashMap.class), HttpStatus.OK);
            return responseEntity;
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException." + e.getMessage());
            return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
            return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
        }
    }

    private ResponseEntity getOidcTokenByCode(String appId, String appSecret, String code, String redirectUri,
                                              String logoutUrl) {
        try {
            // 参数校验
            if (StringUtils.isBlank(appId) || StringUtils.isBlank(appSecret)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "not found the app", null);
            }
            // 用户code获取token必须包含code、redirectUri
            if (StringUtils.isBlank(code) || StringUtils.isBlank(redirectUri)) {
                return resultOidc(HttpStatus.BAD_REQUEST,
                        "when grant_type is authorization_code,parameters must contain code、redirectUri", null);
            }
            // 授权码校验
            String codeMapStr = (String) redisDao.get(code);
            if (StringUtils.isBlank(codeMapStr)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);
            }
            // 授权码信息
            JsonNode jsonNode = objectMapper.readTree(
                    codeMapStr.replace("oidcCode:", ""));
            String appIdTemp = jsonNode.get("appId").asText();
            String redirectUriTemp = jsonNode.get("redirectUri").asText();
            String scopeTemp = jsonNode.get("scope").asText();
            String userId = jsonNode.get("userId").asText();
            // app校验（授权码对应的app）
            if (!appId.equals(appIdTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "client_id invalid", null);
            }
            // app回调地址校验（授权码对应的app的回调地址）
            if (!redirectUri.equals(redirectUriTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "redirect_uri invalid", null);
            }
            // app密码校验
            Application app = authingUserDao.getAppById(appId);
            if (app == null || !app.getSecret().equals(appSecret)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.NOT_FOUND, "app invalid or secret error", null);
            }
            long expire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            HashMap<String, Object> tokens = new HashMap<>();
            tokens.put("access_token", jsonNode.get("accessToken").asText());
            tokens.put("scope", scopeTemp);
            tokens.put("expires_in", expire);
            tokens.put("token_type", "Bearer");
            List<String> scopes = Arrays.asList(scopeTemp.split(" "));
            if (scopes.contains("offline_access")) {
                tokens.put("refresh_token", jsonNode.get("refreshToken").asText());
            }
            String idToken = jsonNode.get("idToken").asText();
            if (scopes.contains("id_token")) {
                tokens.put("id_token", idToken);
            }
            redisDao.remove(code);
            addOidcLogoutUrl(userId, idToken, redirectUri, logoutUrl);
            return new ResponseEntity<>(JSON.parseObject(
                    HtmlUtils.htmlUnescape(JSON.toJSONString(tokens)), HashMap.class), HttpStatus.OK);
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
            redisDao.remove(code);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    /**
     * oidc扩展协议，增加退出接入应用的机制.
     *
     * @param userId 用户id
     * @param idToken idtoken
     * @param redirectUri 重定向url
     * @param logoutUrl 登出url
     */
    private void addOidcLogoutUrl(String userId, String idToken, String redirectUri, String logoutUrl) {
        if (StringUtils.isAnyBlank(userId, idToken, logoutUrl)) {
            return;
        }
        try {
            URL redirect = new URL(redirectUri);
            URL logout = new URL(logoutUrl);
            String redirectDomain = redirect.getHost();
            String logoutDomain = logout.getHost();
            if (!StringUtils.equals(redirectDomain, logoutDomain)) {
                return;
            }

            onlineUserManager.addServiceLogoutUrl(userId, idToken, logoutUrl);
        } catch (MalformedURLException e) {
            LOGGER.error("add oidc logout url failed {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.error("add oidc logout url failed {}", e.getMessage());
        }
    }

    private ResponseEntity resultOidc(HttpStatus status, String msg, Object body) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("status", status.value());
        res.put("error", msg);
        res.put("message", msg);
        if (body != null) {
            res.put("body", body);
        }
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), status);
        return responseEntity;
    }
}
