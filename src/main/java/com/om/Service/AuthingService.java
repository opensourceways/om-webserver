package com.om.Service;

import cn.authing.core.types.Application;
import cn.authing.core.types.User;
import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.LoginFailCounter;
import com.om.Modules.MessageCodeConfig;
import com.om.Modules.ServerErrorException;
import com.om.Modules.authing.AuthingAppSync;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.inter.UserCenterServiceInter;
import com.om.Utils.AuthingUtil;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.LimitUtil;
import com.om.token.ClientSessionManager;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.HtmlUtils;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 身份验证服务类.
 */
@Service("authing")
public class AuthingService implements UserCenterServiceInter {
    /**
     * 使用 @Autowired 注解注入authingUtil.
     */
    @Autowired
    private AuthingUtil authingUtil;

    /**
     * 使用 @Autowired 注解注入环境变量.
     */
    @Autowired
    private Environment env;

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
     * 使用 @Autowired 注解注入 JavaMailSender.
     */
    @Autowired
    private JavaMailSender mailSender;

    /**
     * 使用 @Autowired 注解注入 LimitUtil.
     */
    @Autowired
    private LimitUtil limitUtil;

    /**
     * 使用 @Autowired 注解注入 JwtTokenCreateService.
     */
    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    /**
     * 使用 @Autowired 注解注入 AuthingAppSync.
     */
    @Autowired
    private AuthingAppSync authingAppSync;

    /**
     * 注入三方客户端session管理类.
     */
    @Autowired
    private ClientSessionManager clientSessionManager;

    /**
     * 静态变量: LOGGER - 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingService.class);

    /**
     * 静态变量: CodeUtil实例.
     */
    private static CodeUtil codeUtil;

    /**
     * 静态变量: 错误码映射表.
     */
    private static Map<String, MessageCodeConfig> error2code;

    /**
     * 静态变量: 域名安全性映射表.
     */
    private static HashMap<String, Boolean> domain2secure;

    /**
     * 静态变量: ObjectMapper实例.
     */
    private static ObjectMapper objectMapper;

    /**
     * 静态变量: 结果对象.
     */
    private static Result result;

    /**
     * 静态变量: OneID隐私版本信息.
     */
    private static String oneidPrivacyVersion;

    /**
     * 静态变量: 实例社区信息.
     */
    private static String instanceCommunity;

    /**
     * 用户最大登录数量.
     */
    @Value("${cookie.user.login.maxNum:5}")
    private Integer maxLoginNum;

    /**
     * CodeUtil赋值.
     *
     * @param codeUtil CodeUtil实例
     */
    public static void setCodeUtil(CodeUtil codeUtil) {
        AuthingService.codeUtil = codeUtil;
    }

    /**
     * error2code赋值.
     *
     * @param error2code error2coder实例
     */
    public static void setError2code(Map<String, MessageCodeConfig> error2code) {
        AuthingService.error2code = error2code;
    }

    /**
     * ObjectMapper实例赋值.
     *
     * @param objectMapper objectMapper实例
     */
    public static void setObjectMapper(ObjectMapper objectMapper) {
        AuthingService.objectMapper = objectMapper;
    }

    /**
     * Domain2secure实例赋值.
     *
     * @param domain2secure domain2secure实例
     */
    public static void setDomain2secure(HashMap<String, Boolean> domain2secure) {
        AuthingService.domain2secure = domain2secure;
    }

    /**
     * 结果对象赋值.
     *
     * @param result 结果对象实例
     */
    public static void setResult(Result result) {
        AuthingService.result = result;
    }

    /**
     * oneid隐私版本信息赋值.
     *
     * @param oneidPrivacyVersion oneid隐私版本信息
     */
    public static void setOneidPrivacyVersion(String oneidPrivacyVersion) {
        AuthingService.oneidPrivacyVersion = oneidPrivacyVersion;
    }

    /**
     * 实例社区赋值.
     *
     * @param instanceCommunity 实例社区信息
     */
    public static void setInstanceCommunity(String instanceCommunity) {
        AuthingService.instanceCommunity = instanceCommunity;
    }

    /**
     * 初始化方法.
     */
    @PostConstruct
    public void init() {
        setCodeUtil(new CodeUtil());
        setError2code(MessageCodeConfig.getErrorCode());
        setObjectMapper(new ObjectMapper());
        String domains = env.getProperty("cookie.token.domains");
        String secures = env.getProperty("cookie.token.secures");
        if (domains != null && secures != null) {
            setDomain2secure(HttpClientUtils.getConfigCookieInfo(domains, secures));
        }
        setResult(new Result());
        setOneidPrivacyVersion(env.getProperty("oneid.privacy.version", ""));
        setInstanceCommunity(env.getProperty("community", ""));
    }

    /**
     * 检查账户是否存在的方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String userName = servletRequest.getParameter("username");
        String appId = servletRequest.getParameter("client_id");
        // 校验appId
        if (authingUserDao.getAppById(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, null, "应用不存在", null);
        }
        try {
            // 用户名校验
            if (StringUtils.isBlank(userName)) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
            }
            if (authingUserDao.isUserExists(appId, userName, "username")) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00019, null, null);
            }
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR,
                    MessageCodeConfig.E00048, MessageCodeConfig.E00048.getMsgZh(), null);
        }
        return result(HttpStatus.OK, "success", null);
    }

    /**
     * 发送验证码.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity sendCodeV3(HttpServletRequest servletRequest,
                                     HttpServletResponse servletResponse, boolean isSuccess) {
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
        if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.limit.count", "6"))) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00030.getMsgZh(), null);
        }
        if (!channel.equalsIgnoreCase(Constant.CHANNEL_LOGIN)
                && !channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER)
                && !channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER_BY_PASSWORD)
                && !channel.equalsIgnoreCase(Constant.CHANNEL_RESET_PASSWORD)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00029, null, null);
        }
        // 校验appId
        if (authingUserDao.getAppById(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00047, null, null);
        }
        String accountType = getAccountType(account);
        if (!accountType.equals(Constant.EMAIL_TYPE) && !accountType.equals(Constant.PHONE_TYPE)) {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        String msg = "";
        if (accountType.equals(Constant.EMAIL_TYPE)) {
            msg = channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER_BY_PASSWORD)
                    ? authingUserDao.sendEmailCodeV3(appId, account, "CHANNEL_COMPLETE_EMAIL")
                    : authingUserDao.sendEmailCodeV3(appId, account, channel);
        } else {
            msg = channel.equalsIgnoreCase(Constant.CHANNEL_REGISTER_BY_PASSWORD)
                    ? authingUserDao.sendPhoneCodeV3(appId, account, "CHANNEL_COMPLETE_PHONE")
                    : authingUserDao.sendPhoneCodeV3(appId, account, channel);
        }
        if (!msg.equals("success")) {
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        } else {
            return result(HttpStatus.OK, "success", null);
        }
    }

    /**
     * 注册用户的方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String username = (String) getBodyPara(body, "username");
        String account = (String) getBodyPara(body, "account");
        String code = (String) getBodyPara(body, "code");
        String appId = (String) getBodyPara(body, "client_id");
        String password = (String) getBodyPara(body, "password");
        String acceptPrivacyVersion = (String) getBodyPara(body, "oneidPrivacyAccepted");
        String community = (String) getBodyPara(body, "community");
        // 校验appId
        if (authingUserDao.getAppById(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00047, null, null);
        }
        String msg;
        String accountType;
        try {
            // 用户名校验
            msg = authingUserDao.checkUsername(appId, username, community);
            if (!msg.equals(Constant.SUCCESS)) {
                return result(HttpStatus.BAD_REQUEST, null, msg, null);
            }
            // 邮箱 OR 手机号校验
            accountType = getAccountType(account);
            if (!accountType.equals(Constant.EMAIL_TYPE) && !accountType.equals(Constant.PHONE_TYPE)) {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null);
        }
        // 检查是否同意隐私政策
        if (!"unused".equals(oneidPrivacyVersion) && !oneidPrivacyVersion.equals(acceptPrivacyVersion)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, null);
        }
        if (StringUtils.isNotBlank(password)) {
            // 密码登录
            try {
                password = org.apache.commons.codec.binary.Base64.encodeBase64String(Hex.decodeHex(password));
            } catch (Exception e) {
                LOGGER.error("Hex to Base64 fail. " + e.getMessage());
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
            }
            msg = accountType.equals(Constant.EMAIL_TYPE)
                    ? authingUserDao.registerByEmailPwd(appId, account, password, username, code)
                    : authingUserDao.registerByPhonePwd(appId, account, password, username, code);
        } else if (StringUtils.isNotBlank(code)) {
            // 验证码登录
            msg = accountType.equals(Constant.EMAIL_TYPE)
                    ? authingUserDao.registerByEmailCode(appId, account, code, username)
                    : authingUserDao.registerByPhoneCode(appId, account, code, username);
        } else {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        return msg.equals(Constant.SUCCESS) ? result(HttpStatus.OK, Constant.SUCCESS, null)
                : result(HttpStatus.BAD_REQUEST, null, msg, null);
    }

    /**
     * 验证码登录方法.
     *
     * @param request HTTP请求对象
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity captchaLogin(HttpServletRequest request) {
        String account = request.getParameter("account");
        if (StringUtils.isEmpty(account)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        LoginFailCounter failCounter = limitUtil.initLoginFailCounter(request.getParameter("account"));
        return result(HttpStatus.OK, Constant.SUCCESS, limitUtil.isNeedCaptcha(failCounter));
    }

    /**
     * 登录方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity login(HttpServletRequest servletRequest,
                                HttpServletResponse servletResponse, boolean isSuccess) {
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String appId = (String) getBodyPara(body, "client_id");
        String permission = (String) getBodyPara(body, "permission");
        String account = (String) getBodyPara(body, "account");
        String code = (String) getBodyPara(body, "code");
        String password = (String) getBodyPara(body, "password");
        LoginFailCounter failCounter = limitUtil.initLoginFailCounter(account);
        // 限制一分钟登录失败次数
        if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, limitUtil.loginFail(failCounter));
        }
        // 多次失败需要图片验证码
        if (limitUtil.isNeedCaptcha(failCounter).get(Constant.NEED_CAPTCHA_VERIFICATION) && !isSuccess) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, limitUtil.loginFail(failCounter));
        }
        if (StringUtils.isNotBlank(password)) {
            try {
                password = org.apache.commons.codec.binary.Base64.encodeBase64String(Hex.decodeHex(password));
            } catch (Exception e) {
                LOGGER.error("Hex to Base64 fail. " + e.getMessage());
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
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
            return result(HttpStatus.BAD_REQUEST, null, (String) loginRes, limitUtil.loginFail(failCounter));
        }
        // 登录成功解除登录失败次数限制
        redisDao.remove(account + Constant.LOGIN_COUNT);
        // 资源权限
        String permissionInfo = env.getProperty(Constant.ONEID_VERSION_V1 + "." + permission, "");
        // 获取是否同意隐私
        String oneidPrivacyVersionAccept = authingUserDao.getPrivacyVersionWithCommunity(
                user.getGivenName());
        // 生成token
        String userName = user.getUsername();
        if (Objects.isNull(userName)) {
            userName = "";
        }
        String[] tokens = jwtTokenCreateService.authingUserToken(appId, userId, userName,
                permissionInfo, permission, idToken, oneidPrivacyVersionAccept);

        String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(userId).toString();
        int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
        redisDao.addList(loginKey, idToken, expireSeconds);
        long listSize = redisDao.getListSize(loginKey);
        if (listSize > maxLoginNum) {
            redisDao.removeListTail(loginKey, maxLoginNum);
        }

        // 写cookie
        setCookieLogged(servletRequest, servletResponse, tokens[0], tokens[1]);
        // 返回结果
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", tokens[1]);
        userData.put("photo", user.getPhoto());
        userData.put("username", user.getUsername());
        userData.put("email_exist", StringUtils.isNotBlank(user.getEmail()));
        userData.put("phone_exist", StringUtils.isNotBlank(user.getPhone()));
        userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);
        return result(HttpStatus.OK, "success", userData);
    }

    /**
     * 应用验证方法.
     *
     * @param appId    应用ID
     * @param redirect 重定向URL
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity appVerify(String appId, String redirect) {
        LOGGER.info(String.format("appVerify params: {appId: %s, redirect: %s}", appId, redirect));
        redirect = URLDecoder.decode(redirect);
        List<String> uris = authingAppSync.getAppRedirectUris(appId);
        for (String uri : uris) {
            if (redirect.equals(uri)
                    || (uri.endsWith("*") && redirect.startsWith(uri.substring(0, uri.length() - 1)))) {
                return result(HttpStatus.OK, "success", null);
            }
        }
        return result(HttpStatus.BAD_REQUEST, null, "回调地址与配置不符", null);
    }

    /**
     * 注销重定向URI匹配方法.
     *
     * @param appId    应用ID
     * @param redirect 注销重定向URI
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity logoutRedirectUrisMatch(String appId, String redirect) {
        List<String> uris = authingUserDao.getAppLogoutRedirectUris(appId);
        for (String uri : uris) {
            if (redirect.equals(uri)
                    || (uri.endsWith("*") && redirect.startsWith(uri.substring(0, uri.length() - 1)))) {
                return result(HttpStatus.OK, "success", null);
            }
        }
        return result(HttpStatus.BAD_REQUEST, null, "回调地址与配置不符", null);
    }

    /**
     * Authing用户权限方法.
     *
     * @param community 社区
     * @param token     令牌
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity authingUserPermission(String community, String token) {
        try {
            DecodedJWT decode = JWT.decode(authingUtil.rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            // 获取用户
            User user = authingUserDao.getUser(userId);
            String photo = user.getPhoto();
            String username = user.getUsername();
            String email = user.getEmail();
            String phone = user.getPhone();
            String aigcPrivacyAccepted = Objects.equals(env.getProperty("aigc.privacy.version"),
                    user.getFormatted()) ? user.getFormatted() : "";
            String oneidPrivacyVersionAccept = authingUserDao.getPrivacyVersionWithCommunity(
                    user.getGivenName());
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", photo);
            userData.put("username", username);
            userData.put("email", email);
            userData.put("phone", phone);
            userData.put("aigcPrivacyAccepted", aigcPrivacyAccepted);
            userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 用户权限方法.
     *
     * @param community 社区
     * @param token     令牌
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity userPermissions(String community, String token) {
        try {
            DecodedJWT decode = JWT.decode(authingUtil.rsaDecryptToken(token));
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
                authingUtil.authingUserIdentityIdp(obj, map);
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
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 注销方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String redirectUri = servletRequest.getHeader("Referer");
            String headerToken = servletRequest.getHeader("token");
            String md5Token = DigestUtils.md5DigestAsHex(headerToken.getBytes(StandardCharsets.UTF_8));
            String idTokenKey = "idToken_" + md5Token;
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            String appId = decode.getClaim("client_id").asString();
            // 验证回调是否匹配
            ResponseEntity responseEntity = logoutRedirectUrisMatch(appId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200) {
                return result(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);
            }
            String idToken = (String) redisDao.get(idTokenKey);
            if (StringUtils.isNotBlank(idToken)) {
                String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER)
                        .append(userId).toString();
                redisDao.removeListValue(loginKey, idToken);
            }
            // 退出登录，删除cookie，删除idToken
            String cookieTokenName = env.getProperty("cookie.token.name");
            String verifyTokenName = env.getProperty("cookie.verify.token.name");
            HttpClientUtils.setCookie(servletRequest, servletResponse,
                    verifyTokenName, null, false, 0, "/", domain2secure);
            HttpClientUtils.setCookie(servletRequest, servletResponse,
                    cookieTokenName, null, true, 0, "/", domain2secure);
            clientSessionManager.deleteCookieInConfig(servletResponse);
            redisDao.remove(idTokenKey);
            // 下线用户
            Boolean isLogout = authingUserDao.kickUser(userId);
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("is_logout", isLogout);
            userData.put("client_id", appId);
            userData.put("redirect_uri", redirectUri);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 刷新用户信息的方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity refreshUser(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse, String token) {
        try {
            token = authingUtil.rsaDecryptToken(token);
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
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 检测token.
     *
     * @param token token
     * @return token中用户信息
     */
    @Override
    public ResponseEntity verifyToken(String token) {
        if (StringUtils.isBlank(token)) {
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
        try {
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("userId", userId);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 申请令牌方法.
     *
     * @param httpServletRequest HTTP请求对象
     * @param servletResponse    HTTP响应对象
     * @param community          社区
     * @param code               代码
     * @param permission         权限
     * @param redirectUrl        重定向URL
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity tokenApply(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse, String community,
                                     String code, String permission, String redirectUrl) {
        try {
            String appId = httpServletRequest.getParameter("client_id");
            // 校验appId
            if (authingUserDao.getAppById(appId) == null) {
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
            String userName = (String) user.get("username");
            String phone = (String) user.get("phone_number");
            String email = (String) user.get("email");
            if ("openeuler".equals(instanceCommunity) && StringUtils.isBlank(email)) {
                email = genPredefinedEmail(userId, userName);
            }
            // 获取隐私同意字段值
            String givenName = user.get("given_name") == null ? "" : user.get("given_name").toString();
            String oneidPrivacyVersionAccept = authingUserDao
                    .getPrivacyVersionWithCommunity(givenName);
            // 资源权限
            String permissionInfo = env.getProperty(Constant.ONEID_VERSION_V1 + "." + permission, "");
            if (Objects.isNull(userName)) {
                userName = "";
            }
            // 生成token
            String[] tokens = jwtTokenCreateService.authingUserToken(appId, userId, userName,
                    permissionInfo, permission, idToken, oneidPrivacyVersionAccept);

            String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER)
                    .append(userId).toString();
            int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
            redisDao.addList(loginKey, idToken, expireSeconds);
            long listSize = redisDao.getListSize(loginKey);
            if (listSize > maxLoginNum) {
                redisDao.removeListTail(loginKey, maxLoginNum);
            }

            String token = tokens[0];
            String verifyToken = tokens[1];
            // 写cookie
            String verifyTokenName = env.getProperty("cookie.verify.token.name");
            String cookieTokenName = env.getProperty("cookie.token.name");
            String maxAgeTemp = env.getProperty("authing.cookie.max.age");

            int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : expireSeconds;
            HttpClientUtils.setCookie(httpServletRequest, servletResponse,
                    cookieTokenName, token, true, maxAge, "/", domain2secure);
            HttpClientUtils.setCookie(httpServletRequest, servletResponse,
                    verifyTokenName, verifyToken, false, expireSeconds, "/", domain2secure);
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", verifyToken);
            userData.put("photo", picture);
            userData.put("username", userName);
            userData.put("email_exist", StringUtils.isNotBlank(email));
            userData.put("phone_exist", StringUtils.isNotBlank(phone));
            userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 个人中心用户信息方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity personalCenterUserInfo(HttpServletRequest servletRequest,
                                                 HttpServletResponse servletResponse, String token) {
        try {
            String userId = authingUtil.getUserIdFromToken(token);
            JSONObject userObj = authingUserDao.getUserById(userId);
            HashMap<String, Object> userData = authingUtil.parseAuthingUser(userObj);
            // 返回结果
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }

    }

    /**
     * 删除用户方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity deleteUser(HttpServletRequest servletRequest,
                                     HttpServletResponse servletResponse, String token) {
        try {
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            String photo = authingUserDao.getUser(userId).getPhoto();
            //用户注销
            return authingUserDao.deleteUserById(userId)
                    ? deleteUserAfter(servletRequest, servletResponse, userId, photo)
                    : result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException." + e.getMessage());
            return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        } catch (Exception e) {
            return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        }
    }

    /**
     * 发送验证码方法.
     *
     * @param token     认证令牌
     * @param account   账号
     * @param channel   通道
     * @param isSuccess 是否成功标识
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity sendCode(String token, String account, String channel, boolean isSuccess) {
        // 图片验证码二次校验
        if (!isSuccess) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0002.getMsgZh(), null);
        }
        if (!Constant.AUTHING_CHANNELS.contains(channel.toUpperCase())) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        // 限制1分钟只能发送一次
        String redisKey = account.toLowerCase() + "_sendcode";
        String codeOld = (String) redisDao.get(redisKey);
        if (codeOld != null) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0009.getMsgZh(), null);
        }
        String msg;
        String accountType = getAccountType(account);
        try {
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String appId = decode.getClaim("client_id").asString();
            String userId = decode.getAudience().get(0);
            User user = authingUserDao.getUser(userId);
            String emailInDb = user.getEmail();
            if (accountType.equals("email")
                    && StringUtils.isNotBlank(emailInDb)
                    && emailInDb.endsWith(Constant.AUTO_GEN_EMAIL_SUFFIX)) {
                msg = sendSelfDistributedCode(account, accountType, "CodeBindEmail");
            } else if (accountType.equals("email")) {
                msg = authingUserDao.sendEmailCodeV3(appId, account, channel);
            } else if (accountType.equals("phone")) {
                msg = authingUserDao.sendPhoneCodeV3(appId, account, channel);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (RuntimeException e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e.getMessage());
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);
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

    private String sendSelfDistributedCode(String account, String accountType, String channel) {
        String redisKey = account.toLowerCase() + "_" + channel;
        try {
            // 邮箱or手机号格式校验，并获取验证码过期时间
            long codeExpire;
            String accountTypeCheck = getAccountType(account);
            if (accountTypeCheck.equals("email")) {
                codeExpire = Long.parseLong(env.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
            } else if (accountTypeCheck.equals("phone")) {
                codeExpire = Long.parseLong(env.getProperty("msgsms.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
            } else {
                return accountTypeCheck;
            }
            // 限制1分钟只能发送一次 （剩余的过期时间 + 60s > 验证码过期时间，表示一分钟之内发送过验证码）
            long limit = Long.parseLong(env.getProperty("send.code.limit.seconds", Constant.DEFAULT_EXPIRE_SECOND));
            long remainingExpirationSecond = redisDao.expire(redisKey);
            if (remainingExpirationSecond + limit > codeExpire) {
                return MessageCodeConfig.E0009.getMsgZh();
            }
            // 发送验证码
            String[] strings = codeUtil.sendCode(accountType, account, mailSender, env, "");
            if (StringUtils.isBlank(strings[0]) || !strings[2].equals("send code success")) {
                return MessageCodeConfig.E0008.getMsgZh();
            }
            redisDao.set(redisKey, strings[0], Long.parseLong(strings[1]));
            return "success";
        } catch (Exception ex) {
            return MessageCodeConfig.E0008.getMsgZh();
        }
    }

    /**
     * 发送解绑验证码方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest,
                                         HttpServletResponse servletResponse, boolean isSuccess) {
        String account = servletRequest.getParameter("account");
        String accountType = servletRequest.getParameter("account_type");
        // 图片验证码二次校验
        if (!isSuccess) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0002.getMsgZh(), null);
        }
        if ("phone".equals(accountType)) {
            String phoneCountryCode = authingUserDao.getPhoneCountryCode(account);
            account = phoneCountryCode + authingUserDao.getPurePhone(account);
        }
        String res = sendSelfDistributedCode(account, accountType, "CodeUnbind");
        return res.equals("success") ? result(HttpStatus.OK, "success", null)
                : result(HttpStatus.BAD_REQUEST, null, res, null);
    }

    /**
     * 更新账户信息方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity updateAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse, String token) {
        String oldAccount = servletRequest.getParameter("oldaccount");
        String oldCode = servletRequest.getParameter("oldcode");
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");
        if (StringUtils.isBlank(oldAccount) || StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        //账号格式校验
        if ((!account.matches(Constant.PHONEREGEX) && !account.matches(Constant.EMAILREGEX))
            || (!oldAccount.matches(Constant.PHONEREGEX) && !oldAccount.matches(Constant.EMAILREGEX))) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        if (accountType.toLowerCase().equals("email") && oldAccount.equals(account)) {
            return result(HttpStatus.BAD_REQUEST, null, "新邮箱与已绑定邮箱相同", null);
        } else if (accountType.toLowerCase().equals("phone") && oldAccount.equals(account)) {
            return result(HttpStatus.BAD_REQUEST, null, "新手机号与已绑定手机号相同", null);
        }
        String res = authingUserDao.updateAccount(token, oldAccount, oldCode, account, code, accountType);
        return message(res);
    }

    /**
     * 解绑账户方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity unbindAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse, String token) {
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");
        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        String redisKeyPrefix = account;
        if ("phone".equals(accountType)) {
            String phoneCountryCode = authingUserDao.getPhoneCountryCode(account);
            account = authingUserDao.getPurePhone(account);
            redisKeyPrefix = phoneCountryCode + account;
            // TODO currently international phone skip code verify
            if (!"+86".equals(phoneCountryCode)) {
                String res = authingUserDao.unbindAccount(token, account, accountType);
                return res.equals("unbind success") ? result(HttpStatus.OK, res, null)
                        : result(HttpStatus.BAD_REQUEST, null, res, null);
            }
        }
        String redisKey = redisKeyPrefix + "_CodeUnbind";
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

    /**
     * 绑定账户方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity bindAccount(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse, String token) {
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");
        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        //账号格式校验
        if (!account.matches(Constant.PHONEREGEX) && !account.matches(Constant.EMAILREGEX)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        return message(authingUserDao.bindAccount(token, account, code, accountType));
    }

    /**
     * 绑定连接列表方法.
     *
     * @param token 令牌
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity linkConnList(String token) {
        List<Map<String, String>> res = authingUserDao.linkConnList(token);
        return (res == null) ? result(HttpStatus.UNAUTHORIZED, "get connections fail", null)
                : result(HttpStatus.OK, "get connections success", res);
    }

    /**
     * 绑定账户方法.
     *
     * @param token       第一个令牌
     * @param secondtoken 第二个令牌
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity linkAccount(String token, String secondtoken) {
        return message(authingUserDao.linkAccount(token, secondtoken));
    }

    /**
     * 解除账户绑定方法.
     *
     * @param token    令牌
     * @param platform 平台
     * @param community 社区
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity unLinkAccount(String token, String platform, String community) {
        String msg = authingUserDao.unLinkAccount(token, platform, community);
        return msg.equals("success") ? result(HttpStatus.OK, "unlink account success", null)
                : result(HttpStatus.BAD_REQUEST, null, msg, null);
    }

    /**
     * 更新用户基本信息方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @param map             用户信息映射
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity updateUserBaseInfo(HttpServletRequest servletRequest,
                                             HttpServletResponse servletResponse,
                                             String token, Map<String, Object> map) {
        String res;
        try {
            res = authingUserDao.updateUserBaseInfo(token, map);
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, "Internal Server Error", null);
        }
        return res.equals("success") ? result(HttpStatus.OK, "update base info success", null)
                : result(HttpStatus.BAD_REQUEST, null, res, null);
    }

    /**
     * 更新照片方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @param file            上传的文件
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity updatePhoto(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse, String token, MultipartFile file) {
        return authingUserDao.updatePhoto(token, file)
                ? result(HttpStatus.OK, "update photo success", null)
                : result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    /**
     * 获取公钥方法.
     *
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity getPublicKey() {
        String msg = authingUserDao.getPublicKey();
        try {
            return (msg.equals(MessageCodeConfig.E00048.getMsgEn()))
                    ? result(HttpStatus.INTERNAL_SERVER_ERROR, null, msg, null)
                    : result(HttpStatus.OK, Constant.SUCCESS, objectMapper.readTree(msg));
        } catch (JsonProcessingException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, null, msg, null);
        }
    }

    /**
     * 更新密码方法.
     *
     * @param servletRequest HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity updatePassword(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String msg = MessageCodeConfig.E00050.getMsgZh();
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
            String oldPwd = (String) getBodyPara(body, "old_pwd");
            String newPwd = (String) getBodyPara(body, "new_pwd");
            if (StringUtils.isBlank(newPwd)) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
            }
            Cookie cookie = authingUtil.getCookie(servletRequest, env.getProperty("cookie.token.name"));
            msg = authingUserDao.updatePassword(cookie.getValue(), oldPwd, newPwd);
            if (msg.equals("success")) {
                String token = authingUtil.rsaDecryptToken(cookie.getValue());
                DecodedJWT decode = JWT.decode(token);
                String userId = decode.getAudience().get(0);
                logoutAllSessions(userId, servletRequest, servletResponse);
                authingUserDao.kickUser(userId);
                return result(HttpStatus.OK, "success", null);
            }
        } catch (RuntimeException e) {
            LOGGER.error("update password failed {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.error("update password failed {}", e.getMessage());
        }
        return result(HttpStatus.BAD_REQUEST, null, msg, null);
    }

    /**
     * 重置密码验证方法.
     *
     * @param request HTTP请求对象
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity resetPwdVerify(HttpServletRequest request) {
        Object msg = MessageCodeConfig.E00012.getMsgZh();
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(request);
            String account = (String) getBodyPara(body, "account");
            String code = (String) getBodyPara(body, "code");
            String appId = (String) getBodyPara(body, "client_id");
            // 校验appId
            Application app = authingUserDao.getAppById(appId);
            if (app == null) {
                return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00047.getMsgZh(), null);
            }
            // 邮箱手机号验证
            String accountType = getAccountType(account);
            String userId = "";
            if (accountType.equals(Constant.EMAIL_TYPE)) {
                msg = authingUserDao.resetPwdVerifyEmail(appId, account, code);
                userId = authingUserDao.getUserIdByEmail(account);
            } else if (accountType.equals(Constant.PHONE_TYPE)) {
                msg = authingUserDao.resetPwdVerifyPhone(appId, account, code);
                userId = authingUserDao.getUserIdByPhone(account);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
            // 获取修改密码的token
            if (msg instanceof JSONObject resetToken) {
                int expireTime = resetToken.getInt("tokenExpiresIn");
                String tokenKey = Constant.REDIS_PREFIX_RESET_PASSWD + resetToken.getString("passwordResetToken");
                if (StringUtils.isNotBlank(userId) && expireTime > 0) {
                    redisDao.set(tokenKey, userId, (long) expireTime);
                }
                return result(HttpStatus.OK, Constant.SUCCESS, resetToken.getString("passwordResetToken"));
            }
        } catch (Exception ignored) {
        }
        return result(HttpStatus.BAD_REQUEST, null, msg.toString(), null);
    }

    /**
     * 重置密码方法.
     *
     * @param servletRequest HTTP请求对象
     * @param servletResponse HTTP请求响应对象
     * @return ResponseEntity 响应实体
     */
    @Override
    public ResponseEntity resetPwd(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
            String pwdResetToken = (String) getBodyPara(body, "pwd_reset_token");
            String newPwd = (String) getBodyPara(body, "new_pwd");
            if (StringUtils.isBlank(newPwd)) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
            }
            newPwd = org.apache.commons.codec.binary.Base64.encodeBase64String(Hex.decodeHex(newPwd));
            String tokenKey = Constant.REDIS_PREFIX_RESET_PASSWD + pwdResetToken;
            String userId = (String) redisDao.get(tokenKey);
            if (StringUtils.isBlank(userId)) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
            }
            redisDao.remove(tokenKey);
            String resetMsg = authingUserDao.resetPwd(pwdResetToken, newPwd);
            if (resetMsg.equals(Constant.SUCCESS)) {
                logoutAllSessions(userId, servletRequest, servletResponse);
                authingUserDao.kickUser(userId);
            }
            return resetMsg.equals(Constant.SUCCESS) ? result(HttpStatus.OK, Constant.SUCCESS, null)
                    : result(HttpStatus.BAD_REQUEST, null, resetMsg, null);
        } catch (Exception ignored) {
        }
        return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), status);
        return responseEntity;
    }

    /**
     * 构建响应实体方法.
     *
     * @param status  HTTP状态
     * @param msgCode 消息代码配置
     * @param msg     消息
     * @param data    数据对象
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity result(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data) {
        return result.setResult(status, msgCode, msg, data, error2code);
    }

    /**
     * 构建消息响应实体方法.
     *
     * @param res 消息内容
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity message(String res) {
        switch (res) {
            case "true":
                return result(HttpStatus.OK, "success", null);
            case "false":
                return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
            default:
                if (!res.contains(":")) {
                    return result(HttpStatus.BAD_REQUEST, null, res, null);
                }
                ObjectMapper objectMapper = new ObjectMapper();
                String message = "faild";
                try {
                    res = res.substring(Constant.AUTHING_RES_PREFIX_LENGTH);
                    Iterator<JsonNode> buckets = objectMapper.readTree(res).iterator();
                    if (buckets.hasNext()) {
                        message = buckets.next().get("message").get("message").asText();
                    }
                } catch (JsonProcessingException e) {
                    LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
                    message = e.getMessage();
                }
                return result(HttpStatus.BAD_REQUEST, null, message, null);
        }
    }

    /**
     * 获取账号类型方法.
     *
     * @param account 账号
     * @return String 账号类型
     */
    public String getAccountType(String account) {
        return account.matches(Constant.EMAILREGEX) ? "email"
                : (account.matches(Constant.PHONEREGEX) ? "phone" : "请输入正确的手机号或者邮箱");

    }

    private ResponseEntity deleteUserAfter(HttpServletRequest httpServletRequest,
                                           HttpServletResponse servletResponse,
                                           String userId, String photo) {
        try {
            // 删除用户头像
            authingUserDao.deleteObsObjectByUrl(photo);
            // 删除cookie，删除idToken
            String headerToken = httpServletRequest.getHeader("token");
            String md5Token = DigestUtils.md5DigestAsHex(headerToken.getBytes(StandardCharsets.UTF_8));
            String idTokenKey = "idToken_" + md5Token;
            redisDao.remove(idTokenKey);
            logoutAllSessions(userId, httpServletRequest, servletResponse);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result(HttpStatus.OK, "delete user success", null);
    }

    private Object getBodyPara(Map<String, Object> body, String paraName) {
        return body.getOrDefault(paraName, null);
    }

    /**
     * 登录authing.
     *
     * @param appId 应用id
     * @param account 账号
     * @param code 验证码
     * @param password 密码
     * @return 登录响应体
     */
    public Object login(String appId, String account, String code, String password) {
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
        Application app = authingUserDao.getAppById(appId);
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
                // 用户名校验
                if (StringUtils.isBlank(account) || !account.matches(Constant.USERNAMEREGEX)) {
                    return MessageCodeConfig.E00012.getMsgZh();
                }
                msg = authingUserDao.loginByUsernamePwd(app, account, password);
            }
        } catch (ServerErrorException e) {
            return MessageCodeConfig.E00048.getMsgZh();
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

    /**
     * 根据用户id更新成默认邮件地址.
     *
     * @param userId 用户id
     * @param username 用户名
     * @return 执行结果
     */
    public String genPredefinedEmail(String userId, String username) {
        try {
            if (StringUtils.isBlank(userId) || StringUtils.isBlank(username)) {
                return "";
            }
            String email = username + Constant.AUTO_GEN_EMAIL_SUFFIX;
            return authingUserDao.updateEmailById(userId, email);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return "";
        }
    }

    private void logoutAllSessions(String userId, HttpServletRequest request, HttpServletResponse response) {
        String cookieTokenName = env.getProperty("cookie.token.name");
        String verifyTokenName = env.getProperty("cookie.verify.token.name");
        HttpClientUtils.setCookie(request, response,
                verifyTokenName, null, false, 0, "/", domain2secure);
        HttpClientUtils.setCookie(request, response,
                cookieTokenName, null, true, 0, "/", domain2secure);
        if (StringUtils.isNotBlank(userId)) {
            String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER)
                    .append(userId).toString();
            redisDao.remove(loginKey);
        }
    }
}
