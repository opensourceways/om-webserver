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

package com.om.Service;

import cn.authing.core.types.Application;
import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.LoginFailCounter;
import com.om.Modules.MessageCodeConfig;
import com.om.Modules.ServerErrorException;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.inter.UserCenterServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.LimitUtil;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service("authing")
public class AuthingService implements UserCenterServiceInter {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    JavaMailSender mailSender;

    @Autowired
    LimitUtil limitUtil;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    private static final Logger logger =  LoggerFactory.getLogger(AuthingService.class);

    private static final String OIDCISSUER = "ONEID";

    private static CodeUtil codeUtil;

    private static Map<String, MessageCodeConfig> error2code;

    private static HashMap<String, Boolean> domain2secure;

    private static ObjectMapper objectMapper;

    private static HashMap<String, String[]> oidcScopeOthers;

    private static HashMap<String, String> oidcScopeAuthingMapping;

    private static Result result;

    @PostConstruct
    public void init() {
        codeUtil = new CodeUtil();
        error2code = MessageCodeConfig.getErrorCode();
        objectMapper = new ObjectMapper();
        domain2secure = HttpClientUtils.getConfigCookieInfo(Objects.requireNonNull(env.getProperty("cookie.token.domains")), Objects.requireNonNull(env.getProperty("cookie.token.secures")));
        oidcScopeOthers = getOidcScopesOther();
        oidcScopeAuthingMapping = oidcScopeAuthingMapping();
        result = new Result();
    }

    @Override
    public ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String userName = servletRequest.getParameter("username");
        String account = servletRequest.getParameter("account");
        String appId = servletRequest.getParameter("client_id");

        // 校验appId
        if (authingUserDao.initAppClient(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, null, "应用不存在", null);
        }

        try {
            if (StringUtils.isNotBlank(userName)) {
                boolean username = authingUserDao.isUserExists(appId, userName, "username");
                if (username) return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);
            } else if (StringUtils.isNotBlank(account)) {
                String accountType = checkPhoneAndEmail(appId, account);
                if (!accountType.equals("email") && !accountType.equals("phone"))
                    return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048,
                    MessageCodeConfig.E00048.getMsgZh(), null);
        }

        return result(HttpStatus.OK, "success", null);
    }

    @Override
    public ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess) {
        String community = servletRequest.getParameter("community");
        String account = servletRequest.getParameter("account");
        String channel = servletRequest.getParameter("channel");
        String appId = servletRequest.getParameter("client_id");

        // 验证码二次校验
        if (!isSuccess) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, null);
        }

        // 限制一分钟登录失败次数
        String loginErrorCountKey = account + "loginCount";
        Object v = redisDao.get(loginErrorCountKey);
        int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
        if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.limit.count", "6")))
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00030.getMsgZh(), null);

        if (!channel.equalsIgnoreCase(Constant.CHANNEL_LOGIN)
                && !channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER)
                && !channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER_BY_PASSWORD)
                && !channel.equalsIgnoreCase(Constant.CHANNEL_RESET_PASSWORD)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00029, null, null);
        }

        // 校验appId
        if (authingUserDao.initAppClient(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00047, null, null);
        }

        String accountType = getAccountType(account);
        String msg = "";
        if (accountType.equals(Constant.EMAIL_TYPE)) {
            msg = channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER_BY_PASSWORD)
                    ? sendCodeForRegisterByPwd(account, accountType, community, channel)
                    : authingUserDao.sendEmailCodeV3(appId, account, channel);
        } else if (accountType.equals(Constant.PHONE_TYPE)) {
            msg = channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER_BY_PASSWORD)
                    ? sendCodeForRegisterByPwd(account, accountType, community, channel)
                    : authingUserDao.sendPhoneCodeV3(appId, account, channel);
        } else {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }

        if (!msg.equals("success"))
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        else return result(HttpStatus.OK, "success", null);
    }

    @Override
    public ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String community = (String) getBodyPara(body, "community");
        String username = (String) getBodyPara(body, "username");
        String account = (String) getBodyPara(body, "account");
        String code = (String) getBodyPara(body, "code");
        String appId = (String) getBodyPara(body, "client_id");
        String password = (String) getBodyPara(body, "password");

        // 校验appId
        if (authingUserDao.initAppClient(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00047, null, null);
        }

        String msg;
        String accountType;
        try {
            // 用户名校验
            msg = authingUserDao.checkUsername(appId, username);
            if (!msg.equals(Constant.SUCCESS)) {
                return result(HttpStatus.BAD_REQUEST, null, msg, null);
            }

            // 邮箱 OR 手机号校验
            accountType = checkPhoneAndEmail(appId, account);
            if (!accountType.equals(Constant.EMAIL_TYPE) && !accountType.equals(Constant.PHONE_TYPE)) {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null);
        }

        if (StringUtils.isNotBlank(password)) {
            // 密码登录 验证码校验
            String redisKey = account.toLowerCase() + community.toLowerCase() + Constant.CHANNEL_REGISTER_BY_PASSWORD;
            String codeTemp = (String) redisDao.get(redisKey);
            if (codeTemp == null) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0001, null, null);
            }
            if(!code.equals(codeTemp)) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, null);
            }
            // 密码登录
            if (accountType.equals(Constant.EMAIL_TYPE)) {
                msg = authingUserDao.registerByEmailPwd(appId, account, password, username);
            } else {
                msg = authingUserDao.registerByPhonePwd(appId, account, password, username);
            }
        } else if (StringUtils.isNotBlank(code)) {
            // 验证码登录
            if (accountType.equals(Constant.EMAIL_TYPE)) {
                msg = authingUserDao.registerByEmailCode(appId, account, code, username);
            } else {
                msg = authingUserDao.registerByPhoneCode(appId, account, code, username);
            }
        } else {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }

        if (!msg.equals(Constant.SUCCESS)) {
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        }
        return result(HttpStatus.OK, Constant.SUCCESS, null);
    }

    @Override
    public ResponseEntity login(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                boolean isSuccess) {
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String appId = (String) getBodyPara(body, "client_id");
        String permission = (String) getBodyPara(body, "permission");
        String account = (String) getBodyPara(body, "account");
        String code = (String) getBodyPara(body, "code");
        String password = (String) getBodyPara(body, "password");
        String ip = HttpClientUtils.getRemoteIp(servletRequest);
        LoginFailCounter failCounter = limitUtil.initLoginFailCounter(account, ip);

        // 限制一分钟登录失败次数
        if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null,
                    limitUtil.loginFail(failCounter));
        }

        // 多次失败需要图片验证码
        if (limitUtil.isNeedCaptcha(failCounter).get(Constant.NEED_CAPTCHA_VERIFICATION)) {
            if (!isSuccess) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null,
                        limitUtil.loginFail(failCounter));
            }
        }

        // 登录成功返回用户token
        Object loginRes = login(appId, account, code, password);

        // 获取用户信息
        String idToken;
        String userId;
        User user;
        if (loginRes instanceof JSONObject) {
            JSONObject userObj = (JSONObject) loginRes;
            idToken = userObj.getString("id_token");
            userId = JWT.decode(idToken).getSubject();
            user = authingUserDao.getUser(userId);
        } else {
            return result(HttpStatus.BAD_REQUEST, null, (String) loginRes,
                    limitUtil.loginFail(failCounter));
        }

        // 登录成功解除登录失败次数限制
        redisDao.remove(account + Constant.LOGIN_COUNT);

        // 资源权限
        String permissionInfo = env.getProperty(Constant.ONEID_VERSION_V1 + "." + permission);

        // 生成token
        String[] tokens = jwtTokenCreateService.authingUserToken(appId, userId,
                user.getUsername(), permissionInfo, permission, idToken);

        // 写cookie
        setCookieLogged(servletRequest, servletResponse, tokens[0], tokens[1]);

        // 返回结果
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", tokens[1]);
        userData.put("photo", user.getPhoto());
        userData.put("username", user.getUsername());
        userData.put("email_exist", StringUtils.isNotBlank(user.getEmail()));
        return result(HttpStatus.OK, "success", userData);
    }

    public ResponseEntity appVerify(String appId, String redirect) {
        List<String> uris = authingUserDao.getAppRedirectUris(appId);
        for (String uri : uris) {
            if (uri.endsWith("*") && redirect.startsWith(uri.substring(0, uri.length() - 1)))
                return result(HttpStatus.OK, "success", null);
            else if (redirect.equals(uri))
                return result(HttpStatus.OK, "success", null);
        }
        return result(HttpStatus.BAD_REQUEST, null, "回调地址与配置不符", null);
    }

    public ResponseEntity oidcAuth(String token, String appId, String redirectUri, String responseType, String state, String scope) {
        try {
            // responseType校验
            if (!responseType.equals("code"))
                return resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);

            // scope校验
            List<String> scopes = Arrays.asList(scope.split(" "));
            if (!scopes.contains("openid") || !scopes.contains("profile"))
                return resultOidc(HttpStatus.NOT_FOUND, "scope must contain <openid profile>", null);

            // app回调地址校验
            ResponseEntity responseEntity = appVerify(appId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200)
                return resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);

            // 获取登录用户ID
            token = rsaDecryptToken(token);
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
            String codeMapStr = "oidcCode:" + objectMapper.writeValueAsString(codeMap);
            redisDao.set(code, codeMapStr, codeExpire);
            // 缓存 oidcToken
            HashMap<String, String> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessToken);
            userTokenMap.put("refresh_token", refreshToken);
            userTokenMap.put("idToken", idToken);
            userTokenMap.put("scope", scope);
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes()), userTokenMapStr, refreshTokenExpire);

            String res = String.format("%s?code=%s&state=%s", redirectUri, code, state);
            return resultOidc(HttpStatus.OK, "OK", res);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    public ResponseEntity oidcAuthorize(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        try {
            Map<String, String[]> parameterMap = servletRequest.getParameterMap();
            String clientId = parameterMap.getOrDefault("client_id", new String[]{""})[0];
            String responseType = parameterMap.getOrDefault("response_type", new String[]{""})[0];
            String redirectUri = parameterMap.getOrDefault("redirect_uri", new String[]{""})[0];
            String scope = parameterMap.getOrDefault("scope", new String[]{""})[0];
            String state = parameterMap.getOrDefault("state", new String[]{""})[0];

            // responseType校验
            if (!responseType.equals("code"))
                return resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);

            // app回调地址校验
            ResponseEntity responseEntity = appVerify(clientId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200)
                return resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);

            // 若缺少state,后端自动生成
            state = StringUtils.isNotBlank(state) ? state : UUID.randomUUID().toString().replaceAll("-", "");

            // scope默认<openid profile>
            scope = StringUtils.isBlank(scope) ? "openid profile" : scope;

            // 重定向到登录页
            String loginPage = env.getProperty("oidc.login.page");
            String loginPageRedirect = String.format("%s?client_id=%s&scope=%s&redirect_uri=%s&response_mode=query&state=%s", loginPage, clientId, scope, redirectUri, state);
            servletResponse.sendRedirect(loginPageRedirect);

            return resultOidc(HttpStatus.OK, "OK", loginPageRedirect);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

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
                    String[] split = new String(authorization).split(":");
                    appId = split[0];
                    appSecret = split[1];
                }
                String redirectUri = parameterMap.getOrDefault("redirect_uri", new String[]{""})[0];
                String code = parameterMap.getOrDefault("code", new String[]{""})[0];
                return getOidcTokenByCode(appId, appSecret, code, redirectUri);
            } else if (grantType.equals("password")) {
                String appId;
                String appSecret;
                if (parameterMap.containsKey("client_id") && parameterMap.containsKey("client_secret")) {
                    appId = parameterMap.getOrDefault("client_id", new String[]{""})[0];
                    appSecret = parameterMap.getOrDefault("client_secret", new String[]{""})[0];
                } else {
                    String header = servletRequest.getHeader("Authorization");
                    byte[] authorization = Base64.getDecoder().decode(header.replace("Basic ", ""));
                    String[] split = new String(authorization).split(":");
                    appId = split[0];
                    appSecret = split[1];
                }
                String redirectUri = parameterMap.getOrDefault("redirect_uri", new String[]{""})[0];
                String account = parameterMap.getOrDefault("account", new String[]{""})[0];
                String password = parameterMap.getOrDefault("password", new String[]{""})[0];
                String scope =  parameterMap.getOrDefault("scope", new String[]{""})[0];
                return getOidcTokenByPassword(appId, appSecret, account, password, redirectUri, scope);
            } else if (grantType.equals("refresh_token")) {
                String refreshToken = parameterMap.getOrDefault("refresh_token", new String[]{""})[0];
                return oidcRefreshToken(refreshToken);
            } else
                return resultOidc(HttpStatus.BAD_REQUEST, "grant_type must be authorization_code or refresh_token", null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            redisDao.remove("code");
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    public ResponseEntity userByAccessToken(HttpServletRequest servletRequest) {
        try {
            String authorization = servletRequest.getHeader("Authorization");
            if (StringUtils.isBlank(authorization)) {
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            }
            String accessToken = authorization.replace("Bearer ", "");

            // 解析access_token
            String token = rsaDecryptToken(accessToken);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();

            // token是否被刷新了或者已经过期
            Object refreshedToken = redisDao.get(DigestUtils.md5DigestAsHex(accessToken.getBytes()));
            if (refreshedToken != null || expiresAt.before(new Date()))
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);

            // 获取用户
            JSONObject userObj = authingUserDao.getUserById(userId);

            // 根据scope获取用户信息 oidcScopeAuthingMapping(临时,字段映射)
            HashMap<String, Object> userData = new HashMap<>();
            HashMap<String, Object> addressMap = new HashMap<>();
            // 1、默认字段
            String[] profiles = env.getProperty("oidc.scope.profile", "").split(",");
            for (String profile : profiles) {
                String profileTemp = oidcScopeAuthingMapping.getOrDefault(profile, profile);
                Object value = jsonObjObjectValue(userObj, profileTemp);
                if (profile.equals("updated_at") && value != null) {
                    DateTimeFormatter df = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    value = LocalDateTime.parse(value.toString(), df).toInstant(ZoneOffset.UTC).toEpochMilli();
                }
                userData.put(profile, value);
            }
            // 2、指定字段
            String[] scopes = decode.getClaim("scope").asString().split(" ");
            for (String scope : scopes) {
                if (scope.equals("openid") || scope.equals("profile")) continue;
                // 三方登录字段
                if (scope.equals("identities")) {
                    ArrayList<Map<String, Object>> identities = authingUserIdentity(userObj);
                    userData.put("identities", identities);
                    continue;
                }
                String[] claims = oidcScopeOthers.getOrDefault(scope, new String[]{scope});
                for (String claim : claims) {
                    String profileTemp = oidcScopeAuthingMapping.getOrDefault(claim, claim);
                    Object value = jsonObjObjectValue(userObj, profileTemp);
                    if (scope.equals("address")) addressMap.put(claim, value);
                    else userData.put(claim, value);
                }
                if (scope.equals("address")) userData.put(scope, addressMap);
            }
            HashMap<String, Object> res = new HashMap<>();
            res.put("code", 200);
            res.put("data", userData);
            res.put("msg", "OK");
            res.putAll(userData);
            return new ResponseEntity<>(res, HttpStatus.OK);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    public ResponseEntity authingUserPermission(String community, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);

            // 获取用户
            User user = authingUserDao.getUser(userId);
            String photo = user.getPhoto();
            String username = user.getUsername();
            String email = user.getEmail();

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", photo);
            userData.put("username", username);
            userData.put("email", email);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    public ResponseEntity userPermissions(String community, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);

            // 获取权限
            ArrayList<String> permissions = new ArrayList<>();
            ArrayList<String> pers = authingUserDao.getUserPermission(userId, env.getProperty("openeuler.groupCode"));
            for (String per : pers) {
                String[] perList = per.split(":");
                if (perList.length > 1) {
                    permissions.add(perList[0] + perList[1]);
                }
            }

            //获取企业信息
            ArrayList<String> companyNameList = new ArrayList<>();
            JSONObject userObj = authingUserDao.getUserById(userId);
            HashMap<String, Map<String, Object>> map = new HashMap<>();
            JSONArray jsonArray = userObj.getJSONArray("identities");
            for (Object o : jsonArray) {
                JSONObject obj = (JSONObject) o;
                authingUserIdentityIdp(obj, map);
            }

            // 获取用户
            User user = authingUserDao.getUser(userId);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();

            userData.put("permissions", permissions);
            userData.put("username", user.getUsername());
            userData.put("companyList", companyNameList);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    @Override
    public ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String headerToken = servletRequest.getHeader("token");
            String md5Token = DigestUtils.md5DigestAsHex(headerToken.getBytes());
            String idTokenKey = "idToken_" + md5Token;
            String idToken = (String) redisDao.get(idTokenKey);

            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();
            String appId = decode.getClaim("client_id").asString();

            // 退出登录，该token失效
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 退出登录，删除cookie，删除idToken
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(servletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(idTokenKey);

            Application app = authingUserDao.getAppById(appId);
            if (app == null) {
                return result(HttpStatus.BAD_REQUEST, null, "退出登录失败", null);
            }

            HashMap<String, Object> userData = new HashMap<>();
            userData.put("id_token", idToken);
            userData.put("client_id", appId);
            userData.put("client_identifier", app.getIdentifier());

            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    @Override
    public ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);

            // 获取用户
            User user = authingUserDao.getUser(userId);
            String photo = user.getPhoto();
            String username = user.getUsername();

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", photo);
            userData.put("username", username);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    public ResponseEntity tokenApply(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse,
                                     String community, String code, String permission, String redirectUrl) {
        try {
            String appId = httpServletRequest.getParameter("client_id");

            // 校验appId
            if (authingUserDao.initAppClient(appId) == null) {
                return result(HttpStatus.BAD_REQUEST, null, "应用不存在", null);
            }

            // 将URL中的中文转码，因为@RequestParam会自动解码，而我们需要未解码的参数
            String url = redirectUrl;
            Matcher matcher = Pattern.compile("[\\u4e00-\\u9fa5]+").matcher(redirectUrl);
            String tmp = "";
            while (matcher.find()) {
                tmp = matcher.group();
                System.out.println(tmp);
                url = url.replaceAll(tmp, URLEncoder.encode(tmp, "UTF-8"));
            }

            // 通过code获取access_token，再通过access_token获取用户
            Map user = authingUserDao.getUserInfoByAccessToken(appId, code, url);
            if (user == null) {
                return result(HttpStatus.UNAUTHORIZED, "user not found", null);
            }

            String userId = user.get("sub").toString();
            String idToken = user.get("id_token").toString();
            String picture = user.get("picture").toString();
            String username = (String) user.get("username");
            String email = (String) user.get("email");

            // 资源权限
            String permissionInfo = env.getProperty(Constant.ONEID_VERSION_V1 + "." + permission);

            // 生成token
            String[] tokens = jwtTokenCreateService.authingUserToken(appId, userId,
                    username, permissionInfo, permission, idToken);
            String token = tokens[0];
            String verifyToken = tokens[1];

            // 写cookie
            String verifyTokenName = env.getProperty("cookie.verify.token.name");
            String cookieTokenName = env.getProperty("cookie.token.name");
            String maxAgeTemp = env.getProperty("authing.cookie.max.age");
            int expire = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
            int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : expire;
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName,
                    token, true, maxAge, "/", domain2secure);
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, verifyTokenName,
                    verifyToken, false, expire, "/", domain2secure);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", verifyToken);
            userData.put("photo", picture);
            userData.put("username", username);
            userData.put("email_exist", StringUtils.isNotBlank(email));
            return result(HttpStatus.OK, "success", userData);

        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    @Override
    public ResponseEntity personalCenterUserInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String userId = getUserIdFromToken(token);
            JSONObject userObj = authingUserDao.getUserById(userId);
            HashMap<String, Object> userData = parseAuthingUser(userObj);
            // 返回结果
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }

    }

    @Override
    public ResponseEntity deleteUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();
            String photo = authingUserDao.getUser(userId).getPhoto();

            //用户注销
            boolean res = authingUserDao.deleteUserById(userId);
            if (res)
                return deleteUserAfter(servletRequest, servletResponse, token, userId, issuedAt, photo);
            else return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        } catch (Exception e) {
            return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        }
    }

    public ResponseEntity sendCode(String token, String account, String channel, boolean isSuccess) {
        // 图片验证码二次校验
        if (!isSuccess)
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0002.getMsgZh(), null);

        // 限制1分钟只能发送一次
        String redisKey = account.toLowerCase() + "_sendcode";
        String codeOld = (String) redisDao.get(redisKey);
        if (codeOld != null) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0009.getMsgZh(), null);
        }

        String msg;
        String accountType = getAccountType(account);
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String appId = decode.getClaim("client_id").asString();
            if (accountType.equals("email")) {
                msg = authingUserDao.sendEmailCodeV3(appId, account, channel);
            } else if (accountType.equals("phone")) {
                msg = authingUserDao.sendPhoneCodeV3(appId, account, channel);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (Exception e) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);
        }

        if (!msg.equals("success")) {
            redisDao.set(redisKey, "code", 60L);
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        } else {
            return result(HttpStatus.OK, "success", null);
        }
    }

    @Override
    public ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                         boolean isSuccess) {
        String account = servletRequest.getParameter("account");
        String accountType = servletRequest.getParameter("account_type");

        // 图片验证码二次校验
        if (!isSuccess)
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0002.getMsgZh(), null);

        String redisKey = account.toLowerCase() + "_CodeUnbind";
        try {
            // 邮箱or手机号格式校验，并获取验证码过期时间
            long codeExpire;
            String accountTypeCheck = getAccountType(account);
            if (accountTypeCheck.equals("email")) {
                codeExpire = Long.parseLong(env.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
            } else if (accountTypeCheck.equals("phone")) {
                codeExpire = Long.parseLong(env.getProperty("msgsms.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
            } else {
                return result(HttpStatus.BAD_REQUEST, null, accountTypeCheck, null);
            }

            // 限制1分钟只能发送一次 （剩余的过期时间 + 60s > 验证码过期时间，表示一分钟之内发送过验证码）
            long limit = Long.parseLong(env.getProperty("send.code.limit.seconds", Constant.DEFAULT_EXPIRE_SECOND));
            long remainingExpirationSecond = redisDao.expire(redisKey);
            if (remainingExpirationSecond + limit > codeExpire) {
                return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0009.getMsgZh(), null);
            }

            // 发送验证码
            String[] strings = codeUtil.sendCode(accountType, account, mailSender, env, "");
            if (StringUtils.isBlank(strings[0]) || !strings[2].equals("send code success"))
                return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);

            redisDao.set(redisKey, strings[0], Long.parseLong(strings[1]));
            return result(HttpStatus.OK, strings[2], null);
        } catch (Exception ex) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);
        }
    }

    @Override
    public ResponseEntity updateAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String oldAccount = servletRequest.getParameter("oldaccount");
        String oldCode = servletRequest.getParameter("oldcode");
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");

        if (StringUtils.isBlank(oldAccount) || StringUtils.isBlank(account) || StringUtils.isBlank(accountType))
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        if (accountType.toLowerCase().equals("email") && oldAccount.equals(account))
            return result(HttpStatus.BAD_REQUEST, null, "新邮箱与已绑定邮箱相同", null);
        else if (accountType.toLowerCase().equals("phone") && oldAccount.equals(account))
            return result(HttpStatus.BAD_REQUEST, null, "新手机号与已绑定手机号相同", null);

        String res = authingUserDao.updateAccount(token, oldAccount, oldCode, account, code, accountType);
        return message(res);
    }

    @Override
    public ResponseEntity unbindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");

        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType))
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        String redisKey = account + "_CodeUnbind";
        String codeTemp = (String) redisDao.get(redisKey);
        if (codeTemp == null) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码无效或已过期", null);
        }
        if (!codeTemp.equals(code)) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);
        }
        String res = authingUserDao.unbindAccount(token, account, accountType);

        if (res.equals("unbind success")) {
            redisDao.remove(redisKey);
            return result(HttpStatus.OK, res, null);
        }
        return result(HttpStatus.BAD_REQUEST, null, res, null);
    }

    @Override
    public ResponseEntity bindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");

        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType))
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        String res = authingUserDao.bindAccount(token, account, code, accountType);
        return message(res);
    }

    public ResponseEntity linkConnList(String token) {
        List<Map<String, String>> res = authingUserDao.linkConnList(token);
        if (res == null) {
            return result(HttpStatus.UNAUTHORIZED, "get connections fail", null);
        }
        return result(HttpStatus.OK, "get connections success", res);
    }

    public ResponseEntity linkAccount(String token, String secondtoken) {
        String res = authingUserDao.linkAccount(token, secondtoken);
        return message(res);
    }

    public ResponseEntity unLinkAccount(String token, String platform) {
        String msg = authingUserDao.unLinkAccount(token, platform);
        if (!msg.equals("success")) {
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        }
        return result(HttpStatus.OK, "unlink account success", null);
    }

    @Override
    public ResponseEntity updateUserBaseInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token, Map<String, Object> map) {
        String res;
        try {
            res = authingUserDao.updateUserBaseInfo(token, map);
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048,
                    "Internal Server Error", null);
        }

        if (res.equals("success"))
            return result(HttpStatus.OK, "update base info success", null);
        else return result(HttpStatus.BAD_REQUEST, null, res, null);
    }

    @Override
    public ResponseEntity updatePhoto(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token, MultipartFile file) {
        boolean res = authingUserDao.updatePhoto(token, file);
        if (res) return result(HttpStatus.OK, "update photo success", null);
        else return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    public ResponseEntity getPublicKey() {
        String msg = authingUserDao.getPublicKey();
        try {
            if (!msg.equals(MessageCodeConfig.E00048.getMsgEn())) {
                return result(HttpStatus.OK, Constant.SUCCESS, objectMapper.readTree(msg));
            } else {
                return result(HttpStatus.INTERNAL_SERVER_ERROR, null, msg, null);
            }
        } catch (JsonProcessingException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, null, msg, null);
        }
    }

    public ResponseEntity updatePassword(HttpServletRequest request) {
        String msg = MessageCodeConfig.E00050.getMsgZh();
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(request);
            String oldPwd = (String) getBodyPara(body, "old_pwd");
            String newPwd = (String) getBodyPara(body, "new_pwd");
            Cookie cookie = getCookie(request, env.getProperty("cookie.token.name"));

            msg = authingUserDao.updatePassword(cookie.getValue(), oldPwd, newPwd);
            if (msg.equals("success")) {
                return result(HttpStatus.OK, "success", null);
            }
        } catch (Exception ignored) {
        }
        return result(HttpStatus.BAD_REQUEST, null, msg, null);
    }

    public ResponseEntity resetPwdVerify(HttpServletRequest request) {
        Object msg = MessageCodeConfig.E00012.getMsgZh();
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(request);
            String account = (String) getBodyPara(body, "account");
            String code = (String) getBodyPara(body, "code");
            String appId = (String) getBodyPara(body, "client_id");

            // 校验appId
            Application app = authingUserDao.initAppClient(appId);
            if (app == null) {
                return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00047.getMsgZh(), null);
            }

            // 邮箱手机号验证
            String accountType = getAccountType(account);
            if (accountType.equals(Constant.EMAIL_TYPE)) {
                msg = authingUserDao.resetPwdVerifyEmail(appId, account, code);
            } else if (accountType.equals(Constant.PHONE_TYPE)) {
                msg = authingUserDao.resetPwdVerifyPhone(appId, account, code);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }

            // 获取修改密码的token
            if (msg instanceof JSONObject) {
                JSONObject resetToken = (JSONObject) msg;
                return result(HttpStatus.OK, Constant.SUCCESS, resetToken.getString("passwordResetToken"));
            }
        } catch (Exception ignored) {
        }

        return result(HttpStatus.BAD_REQUEST, null, msg.toString(), null);
    }

    public ResponseEntity resetPwd(HttpServletRequest request) {
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(request);
            String pwdResetToken = (String) getBodyPara(body, "pwd_reset_token");
            String newPwd = (String) getBodyPara(body, "new_pwd");

            String resetMsg = authingUserDao.resetPwd(pwdResetToken, newPwd);
            if (resetMsg.equals(Constant.SUCCESS)) {
                return result(HttpStatus.OK, Constant.SUCCESS, null);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, resetMsg, null);
            }
        } catch (Exception ignored) {
        }
        return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
    }

    // 获取自定义token中的user id
    private String getUserIdFromToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
        return decode.getAudience().get(0);
    }

    // 解密RSA加密过的token
    private String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
        return RSAUtil.privateDecrypt(token, privateKey);
    }

    // 解析authing user
    private HashMap<String, Object> parseAuthingUser(JSONObject userObj) {
        HashMap<String, Object> userData = new HashMap<>();

        userData.put("username", jsonObjStringValue(userObj, "username"));
        userData.put("email", jsonObjStringValue(userObj, "email"));
        userData.put("phone", jsonObjStringValue(userObj, "phone"));
        userData.put("signedUp", jsonObjStringValue(userObj, "signedUp"));
        userData.put("nickname", jsonObjStringValue(userObj, "nickname"));
        userData.put("company", jsonObjStringValue(userObj, "company"));
        userData.put("photo", jsonObjStringValue(userObj, "photo"));
        ArrayList<Map<String, Object>> identities = authingUserIdentity(userObj);
        userData.put("identities", identities);

        return userData;
    }

    // identities 解析（包括gitee,github,wechat）
    private ArrayList<Map<String, Object>> authingUserIdentity(JSONObject userObj) {
        ArrayList<Map<String, Object>> res = new ArrayList<>();
        HashMap<String, Map<String, Object>> map = new HashMap<>();
        try {
            JSONArray jsonArray = userObj.getJSONArray("identities");
            for (Object o : jsonArray) {
                JSONObject obj = (JSONObject) o;
                authingUserIdentityIdp(obj, map);
            }
            res.addAll(map.values());
        } catch (Exception ex) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), ex);
        }
        return res;
    }

    // identities -> userInfoInIdp 解析（包括gitee,github,wechat）
    private void authingUserIdentityIdp(JSONObject identityObj, HashMap<String, Map<String, Object>> map) {
        HashMap<String, Object> res = new HashMap<>();

        JSONObject userInfoInIdpObj = identityObj.getJSONObject("userInfoInIdp");
        String userIdInIdp = identityObj.getString("userIdInIdp");
        res.put("userIdInIdp", userIdInIdp);

        String originConnId = identityObj.getJSONArray("originConnIds").get(0).toString();
        if (originConnId.equals(env.getProperty("social.connId.github"))) {
            String github_login = jsonObjStringValue(userInfoInIdpObj, "profile").replace("https://api.github.com/users/", "");
            res.put("identity", "github");
            res.put("login_name", github_login);
            res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "username"));
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("github", res);
        } else if (originConnId.equals(env.getProperty("enterprise.connId.gitee"))) {
            String gitee_login = userInfoInIdpObj.getJSONObject("customData").getString("giteeLogin");
            res.put("identity", "gitee");
            res.put("login_name", gitee_login);
            res.put("user_name", userInfoInIdpObj.getJSONObject("customData").getString("giteeName"));
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("gitee", res);
        } else if (originConnId.equals(env.getProperty("enterprise.connId.openatom"))) {
            String phone = jsonObjStringValue(userInfoInIdpObj, "phone");
            String email = jsonObjStringValue(userInfoInIdpObj, "email");
            String name = StringUtils.isNotBlank(email) ? email : phone;
            res.put("identity", "openatom");
            res.put("login_name", name);
            res.put("user_name", name);
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("openatom", res);
        }
    }

    // JSONObject获取单个node的值
    private String jsonObjStringValue(JSONObject jsonObj, String nodeName) {
        String res = "";
        try {
            if (jsonObj.isNull(nodeName)) return res;
            Object obj = jsonObj.get(nodeName);
            if (obj != null) res = obj.toString();
        } catch (Exception ex) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), ex);
        }
        return res;
    }

    // JSONObject获取单个node的值
    private Object jsonObjObjectValue(JSONObject jsonObj, String nodeName) {
        Object res = null;
        try {
            if (jsonObj.isNull(nodeName)) return res;
            Object obj = jsonObj.get(nodeName);
            if (obj != null) res = obj;
        } catch (Exception ex) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), ex);
        }
        return res;
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        return new ResponseEntity<>(res, status);
    }

    private ResponseEntity resultOidc(HttpStatus status, String msg, Object body) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("status", status.value());
        res.put("error", msg);
        res.put("message", msg);
        if (body != null)
            res.put("body", body);
        return new ResponseEntity<>(res, status);
    }

    private ResponseEntity result(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data) {
        return result.setResult(status, msgCode, msg, data, error2code);
    }

    private ResponseEntity message(String res) {
        switch (res) {
            case "true":
                return result(HttpStatus.OK, "success", null);
            case "false":
                return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
            default:
                ObjectMapper objectMapper = new ObjectMapper();
                String message = "faild";
                try {
                    res = res.substring(14);
                    Iterator<com.fasterxml.jackson.databind.JsonNode> buckets = objectMapper.readTree(res).iterator();
                    if (buckets.hasNext()) {
                        message = buckets.next().get("message").get("message").asText();
                    }
                } catch (JsonProcessingException e) {
                    logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
                    message = e.getMessage();
                }
                return result(HttpStatus.BAD_REQUEST, null, message, null);
        }
    }

    private String getAccountType(String account) {
        String accountType;
        if (account.matches(Constant.EMAILREGEX))
            accountType = "email";
        else if (account.matches(Constant.PHONEREGEX))
            accountType = "phone";
        else
            accountType = "请输入正确的手机号或者邮箱";

        return accountType;
    }

    private String checkPhoneAndEmail(String appId, String account) throws ServerErrorException {
        String accountType = getAccountType(account);
        if (!accountType.equals("email") && !accountType.equals("phone"))
            return accountType;

        if (authingUserDao.isUserExists(appId, account, accountType))
            return "该账号已注册";
        else
            return accountType;
    }

    private ResponseEntity deleteUserAfter(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse,
                                           String token, String userId, Date issuedAt, String photo) {
        try {
            // 当前token失效
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 删除用户头像
            authingUserDao.deleteObsObjectByUrl(photo);

            // 删除cookie，删除idToken
            String headerToken = httpServletRequest.getHeader("token");
            String md5Token = DigestUtils.md5DigestAsHex(headerToken.getBytes());
            String idTokenKey = "idToken_" + md5Token;
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(idTokenKey);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result(HttpStatus.OK, "delete user success", null);
    }

    private HashMap<String, String[]> getOidcScopesOther() {
        String[] others = env.getProperty("oidc.scope.other", "").split(";");
        HashMap<String, String[]> otherMap = new HashMap<>();
        for (String other : others) {
            if (StringUtils.isBlank(other)) continue;
            String[] split = other.split("->");
            otherMap.put(split[0], split[1].split(","));
        }
        return otherMap;
    }

    private HashMap<String, String> oidcScopeAuthingMapping() {
        String[] mappings = env.getProperty("oidc.scope.authing.mapping", "").split(",");
        HashMap<String, String> authingMapping = new HashMap<>();
        for (String mapping : mappings) {
            if (StringUtils.isBlank(mapping)) continue;
            String[] split = mapping.split(":");
            authingMapping.put(split[0], split[1]);
        }
        return authingMapping;
    }

    private ResponseEntity getOidcTokenByCode(String appId, String appSecret, String code, String redirectUri) {
        try {
            // 参数校验
            if (StringUtils.isBlank(appId) || StringUtils.isBlank(appSecret))
                return resultOidc(HttpStatus.BAD_REQUEST, "not found the app", null);
            // 用户code获取token必须包含code、redirectUri
            if (StringUtils.isBlank(code) || StringUtils.isBlank(redirectUri))
                return resultOidc(HttpStatus.BAD_REQUEST, "when grant_type is authorization_code,parameters must contain code、redirectUri", null);

            // 授权码校验
            String codeMapStr = (String) redisDao.get(code);
            if (StringUtils.isBlank(codeMapStr))
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);

            // 授权码信息
            com.fasterxml.jackson.databind.JsonNode jsonNode = objectMapper.readTree(codeMapStr.replace("oidcCode:", ""));
            String appIdTemp = jsonNode.get("appId").asText();
            String redirectUriTemp = jsonNode.get("redirectUri").asText();
            String scopeTemp = jsonNode.get("scope").asText();

            // app校验（授权码对应的app）
            if (!appId.equals(appIdTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);
            }
            // app回调地址校验（授权码对应的app的回调地址）
            if (!redirectUri.equals(redirectUriTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);
            }
            // app密码校验
            Application app = authingUserDao.getAppById(appId);
            if (app == null || !app.getSecret().equals(appSecret)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.NOT_FOUND, "app invalid or secret error", null);
            }

            long expire = Long.parseLong(
                    env.getProperty("oidc.access.token.expire", "1800"));

            HashMap<String, Object> tokens = new HashMap<>();
            tokens.put("access_token", jsonNode.get("accessToken").asText());
            tokens.put("scope", scopeTemp);
            tokens.put("expires_in", expire);
            tokens.put("token_type", "Bearer");
            List<String> scopes = Arrays.asList(scopeTemp.split(" "));
            if (scopes.contains("offline_access")) {
                tokens.put("refresh_token", jsonNode.get("refreshToken").asText());
            }
            if (scopes.contains("id_token")) {
                tokens.put("id_token", jsonNode.get("idToken").asText());
            }


            redisDao.remove(code);
            return new ResponseEntity(tokens, HttpStatus.OK);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            redisDao.remove(code);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    private ResponseEntity getOidcTokenByPassword(String appId, String appSecret, String account, 
            String password, String redirectUri, String scope) {
        try {
            // 参数校验
            if (StringUtils.isBlank(appId) || StringUtils.isBlank(appSecret))
                return resultOidc(HttpStatus.BAD_REQUEST, "not found the app", null);

            if (StringUtils.isBlank(password) || StringUtils.isBlank(redirectUri))
                return resultOidc(HttpStatus.BAD_REQUEST, "when grant_type is password, parameters must contain password、redirectUri", null);

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
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, null);
            }

            // 用户密码校验
            Object loginRes = login(appId, account, null, password);

            // 获取用户信息
            String idToken;
            String userId;
            if (loginRes instanceof JSONObject) {
                JSONObject userObj = (JSONObject) loginRes;
                idToken = userObj.getString("id_token");
                userId = JWT.decode(idToken).getSubject();
            } else {
                long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
                loginErrorCount += 1;
                redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
                return result(HttpStatus.BAD_REQUEST, null, (String) loginRes, null);
            }

            //登录成功解除登录失败次数限制
            redisDao.remove(loginErrorCountKey);

            // 生成access_token和refresh_token
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, accessTokenExpire, null);
            String refreshToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, refreshTokenExpire, null);

            long expire = Long.parseLong(
                    env.getProperty("oidc.access.token.expire", "1800"));

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
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes()), userTokenMapStr, refreshTokenExpire);

            return new ResponseEntity(tokens, HttpStatus.OK);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    private ResponseEntity oidcRefreshToken(String refreshToken) {
        try {
            if (StringUtils.isBlank(refreshToken))
                return resultOidc(HttpStatus.BAD_REQUEST, "when grant_type is authorization_code,parameters must contain refresh_token", null);

            // 解析refresh_token
            String token = rsaDecryptToken(refreshToken);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();

            // tokens校验
            String refreshTokenKey = DigestUtils.md5DigestAsHex(refreshToken.getBytes());
            String tokenStr = (String) redisDao.get(refreshTokenKey);
            if (StringUtils.isBlank(tokenStr))
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            // refresh_token是否过期
            if (expiresAt.before(new Date()))
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);

            com.fasterxml.jackson.databind.JsonNode jsonNode = objectMapper.readTree(tokenStr.replace("oidcTokens:", ""));
            String scope = jsonNode.get("scope").asText();
            String accessToken = jsonNode.get("access_token").asText();

            // 生成新的accessToken和refreshToken
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessTokenNew = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, accessTokenExpire, null);
            String refreshTokenNew = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, refreshTokenExpire, expiresAt);

            // 缓存新的accessToken和refreshToken
            long expire = Long.parseLong(
                    env.getProperty("oidc.access.token.expire", "1800"));
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
            redisDao.set(DigestUtils.md5DigestAsHex(refreshTokenNew.getBytes()), userTokenMapStr, refreshTokenExpire);

            // 移除以前的refresh_token，并将之前的access_token失效
            redisDao.remove(refreshTokenKey);
            redisDao.set(DigestUtils.md5DigestAsHex(accessToken.getBytes()), accessToken, accessTokenExpire);

            return new ResponseEntity(userTokenMap, HttpStatus.OK);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
        }
    }

    private Object getBodyPara(Map<String, Object> body, String paraName) {
        return body.getOrDefault(paraName, null);
    }

    private Object login(String appId, String account, String code, String password) {
        // code/password 同时传入报错
        if ((StringUtils.isNotBlank(code) && StringUtils.isNotBlank(password))) {
            return MessageCodeConfig.E00012.getMsgZh();
        }

        // 手机 or 邮箱判断
        String accountType = "";
        if (StringUtils.isNotBlank(account)) {
            accountType = getAccountType(account);
        }

        // 校验appId
        Application app = authingUserDao.initAppClient(appId);
        if (app == null) {
            return MessageCodeConfig.E00047.getMsgZh();
        }

        // 登录
        Object msg;
        try {
            if (accountType.equals(Constant.EMAIL_TYPE)) { // 邮箱登录
                msg = StringUtils.isNotBlank(code)
                        ? authingUserDao.loginByEmailCode(app, account, code)
                        : authingUserDao.loginByEmailPwd(app, account, password);
            } else if (accountType.equals(Constant.PHONE_TYPE)) { // 手机号登录
                msg = StringUtils.isNotBlank(code)
                        ? authingUserDao.loginByPhoneCode(app, account, code)
                        : authingUserDao.loginByPhonePwd(app, account, password);
            } else { // 用户名登录
                msg = authingUserDao.loginByUsernamePwd(app, account, password);
            }
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null);
        }

        return msg;
    }

    private void setCookieLogged(HttpServletRequest request, HttpServletResponse response,
                                 String token, String verifyToken) {
        // 写cookie
        String cookieTokenName = env.getProperty("cookie.token.name");
        String verifyTokenName = env.getProperty("cookie.verify.token.name");
        String maxAgeTemp = env.getProperty("authing.cookie.max.age");
        int expire = Integer.parseInt(env.getProperty("authing.token.expire.seconds", Constant.DEFAULT_EXPIRE_SECOND));
        int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : expire;
        HttpClientUtils.setCookie(request, response, cookieTokenName,
                token, true, maxAge, "/", domain2secure);
        HttpClientUtils.setCookie(request, response, verifyTokenName,
                verifyToken, false, expire, "/", domain2secure);
    }

    private Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie cookie = null;
        try {
            Cookie[] cookies = request.getCookies();
            cookie = getCookie(cookies, cookieName);
        } catch (Exception ignored) {
        }
        return cookie;
    }

    private Cookie getCookie(Cookie[] cookies, String cookieName) {
        Cookie cookie = null;
        try {
            for (Cookie cookieEle : cookies) {
                if (cookieEle.getName().equals(cookieName)) {
                    cookie = cookieEle;
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return cookie;
    }

    private String sendCodeForRegisterByPwd(String account, String accountType,
                                            String community, String channel) {
        try {
            long codeExpire = accountType.equals(Constant.EMAIL_TYPE)
                    ? Long.parseLong(env.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND))
                    : Long.parseLong(env.getProperty("msgsms.code.expire", Constant.DEFAULT_EXPIRE_SECOND));

            // 限制1分钟只能发送一次 （剩余的过期时间 + 60s > 验证码过期时间，表示一分钟之内发送过验证码）
            long limit = Long.parseLong(env.getProperty("send.code.limit.seconds", Constant.DEFAULT_EXPIRE_SECOND));
            String redisKey = account.toLowerCase() + community.toLowerCase() + channel.toLowerCase();
            long remainingExpirationSecond = redisDao.expire(redisKey);
            if (remainingExpirationSecond + limit > codeExpire) {
                return MessageCodeConfig.E0009.getMsgZh();
            }

            // 发送验证码
            String[] strings = codeUtil.sendCode(accountType, account, mailSender, env, "");
            if (StringUtils.isBlank(strings[0]) || !strings[2].equals("send code success")) {
                return MessageCodeConfig.E0008.getMsgZh();
            }

            redisDao.set(redisKey, strings[0], codeExpire);
            return "success";
        } catch (Exception e) {
            return MessageCodeConfig.E0008.getMsgZh();
        }
    }
}
