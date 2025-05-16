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

package com.om.service;

import cn.authing.core.types.Application;
import cn.authing.core.types.Identity;
import cn.authing.core.types.UpdateUserInput;
import cn.authing.core.types.User;
import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.dao.AuthingManagerDao;
import com.om.dao.AuthingUserDao;
import com.om.dao.RedisDao;
import com.om.modules.OperateFailCounter;
import com.om.modules.MessageCodeConfig;
import com.om.modules.ServerErrorException;
import com.om.modules.authing.AuthingAppSync;
import com.om.result.Constant;
import com.om.result.Result;
import com.om.service.bean.JwtCreatedParam;
import com.om.service.bean.OnlineUserInfo;
import com.om.service.inter.UserCenterServiceInter;
import com.om.utils.AuthingUtil;
import com.om.utils.CodeUtil;
import com.om.utils.CommonUtil;
import com.om.utils.HttpClientUtils;
import com.om.utils.EncryptionService;
import com.om.utils.LimitUtil;
import com.om.utils.ClientIPUtil;
import com.om.utils.LogUtil;
import com.om.authing.AuthingRespConvert;
import com.om.token.ClientSessionManager;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
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
import org.springframework.util.CollectionUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
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
     * 注入加密服务.
     */
    @Autowired
    private EncryptionService encryptionService;

    /**
     * 注入三方客户端session管理类.
     */
    @Autowired
    private ClientSessionManager clientSessionManager;

    /**
     * 退出APP线程池.
     */
    private static final ExecutorService LOGOUT_EXE = new ThreadPoolExecutor(4, 5,
            60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(10000));

    /**
     * Authing的管理面接口.
     */
    @Autowired
    private AuthingManagerDao authingManagerDao;

    /**
     * 注入隐私操作类.
     */
    @Autowired
    private PrivacyHistoryService privacyHistoryService;

    /**
     * 静态变量: LOGGER - 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingService.class);

    /**
     * redirectUri正则.
     */
    private static Pattern redirectUrlPattern = Pattern.compile("[\\u4e00-\\u9fa5]+");

    /**
     * CodeUtil实例.
     */
    @Autowired
    private CodeUtil codeUtil;

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
     * 应用程序版本号.
     */
    @Value("${app.version:1.0}")
    private String appVersion;

    /**
     * token的盐值.
     */
    @Value("${authing.token.sha256.salt: }")
    private String tokenSalt;

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
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String account = (String) getBodyPara(body, "account");
        account = getAbsoluteAccount(account);
        String channel = (String) getBodyPara(body, "channel");
        String appId = (String) getBodyPara(body, "client_id");

        // 如果请求体里没有，尝试在请求参数里获取
        if (StringUtils.isBlank(account) && StringUtils.isBlank(channel) && StringUtils.isBlank(appId)) {
            account = servletRequest.getParameter("account");
            channel = servletRequest.getParameter("channel");
            appId = servletRequest.getParameter("client_id");
        }

        // 验证码二次校验
        if (!isSuccess) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, null);
        }
        // 限制1分钟只能发送一次
        String redisKey = account.toLowerCase() + "_sendcodeV3";
        String codeOld = (String) redisDao.get(redisKey);
        if (codeOld != null) {
            LogUtil.createLogs("anonymous", "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0009.getMsgZh(), null);
        }
        // 限制一分钟登录失败次数
        String loginErrorCountKey = account + "loginCount";
        Object v = redisDao.get(loginErrorCountKey);
        int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
        if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.limit.count", "6"))) {
            LogUtil.createLogs("anonymous", "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
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
            LogUtil.createLogs("anonymous", "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
            LogUtil.createLogs("anonymous", "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
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
        redisDao.set(redisKey, "code", 60L);
        if (!msg.equals("success")) {
            LogUtil.createLogs(account, "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        } else {
            LogUtil.createLogs(account, "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(servletRequest), "success");
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
        account = getAbsoluteAccount(account);
        String code = (String) getBodyPara(body, "code");
        String appId = (String) getBodyPara(body, "client_id");
        String password = (String) getBodyPara(body, "password");
        String acceptPrivacyVersion = (String) getBodyPara(body, "oneidPrivacyAccepted");
        String ip = ClientIPUtil.getClientIpAddress(servletRequest);
        // 校验appId
        if (authingUserDao.getAppById(appId) == null) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00047, null, null);
        }
        String msg;
        String accountType;
        try {
            // 用户名校验
            msg = authingUserDao.checkUsername(appId, username, instanceCommunity, false);
            if (!msg.equals(Constant.SUCCESS)) {
                return result(HttpStatus.BAD_REQUEST, null, msg, null);
            }
            // 邮箱 OR 手机号校验
            accountType = getAccountType(account);
            if (!accountType.equals(Constant.EMAIL_TYPE) && !accountType.equals(Constant.PHONE_TYPE)) {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
            if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
                LogUtil.createLogs("anonymous", "user register", "register",
                        "The user register phone invalid", ip, "fail");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
            }
        } catch (ServerErrorException e) {
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null);
        }
        // 检查是否同意隐私政策
        if (!"unused".equals(oneidPrivacyVersion) && !oneidPrivacyVersion.equals(acceptPrivacyVersion)) {
            LogUtil.createLogs("anonymous", "user register", "register",
                    "The user register no privacy", ip, "fail");
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        LogUtil.createLogs(username, "accept privacy", "user",
                "User accept privacy version:" + acceptPrivacyVersion + ",appVersion:" + appVersion,
                ip, "success");

        if (!isCodeParmValid(code)) {
            LOGGER.error("param code invalid");
            LogUtil.createLogs("anonymous", "user register", "register",
                    "The user register", ip, "fail");
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }

        if (StringUtils.isNotBlank(password)) {
            // 密码登录
            if (!isPasswdParmValid(password)) {
                LOGGER.error("password is invalid");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
            }
            try {
                password = org.apache.commons.codec.binary.Base64.encodeBase64String(Hex.decodeHex(password));
            } catch (Exception e) {
                LOGGER.error("Hex to Base64 fail. " + e.getMessage());
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
            }
            msg = accountType.equals(Constant.EMAIL_TYPE)
                    ? authingUserDao.registerByEmailPwd(appId, account, password, username, code, ip)
                    : authingUserDao.registerByPhonePwd(appId, account, password, username, code, ip);
            if (msg.equals(Constant.SUCCESS)) {
                LogUtil.createLogs(username, "user register", "register",
                        "The user register By password", ip, "success");
            } else {
                LogUtil.createLogs(username, "user register", "register",
                        "The user register By password", ip, "fail");
            }
        } else if (StringUtils.isNotBlank(code)) {
            // 验证码登录
            msg = accountType.equals(Constant.EMAIL_TYPE)
                    ? authingUserDao.registerByEmailCode(appId, account, code, username, ip)
                    : authingUserDao.registerByPhoneCode(appId, account, code, username, ip);
            if (msg.equals(Constant.SUCCESS)) {
                LogUtil.createLogs(username, "user register", "register",
                        "The user register By code", ip, "success");
            } else {
                LogUtil.createLogs(username, "user register", "register",
                        "The user register By code", ip, "fail");
            }
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
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(request);
        String account = (String) getBodyPara(body, "account");
        account = getAbsoluteAccount(account);
        // 如果请求体里没有，尝试在请求参数里获取
        if (StringUtils.isBlank(account)) {
            account = request.getParameter("account");
        }
        if (StringUtils.isEmpty(account)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        OperateFailCounter failCounter = limitUtil.initLoginFailCounter(account);
        return result(HttpStatus.OK, Constant.SUCCESS, limitUtil.isNeedCaptcha(failCounter));
    }

    /**
     * 获取账号.
     * @param account 原始账号.
     * @return 账号.
     */
    public String getAbsoluteAccount(String account) {
        if (StringUtils.isBlank(account)) {
            return account;
        }
        String absoluteAccount = "";
        if (Constant.EMAIL_TYPE.equals(getAccountType(account))) {
            absoluteAccount = account.toLowerCase();
        } else if (Constant.PHONE_TYPE.equals(getAccountType(account))) {
            absoluteAccount = account.startsWith("+") ? account : ("+86" + account);
        } else {
            absoluteAccount = account;
        }
        return absoluteAccount;
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
        if (StringUtils.isAnyBlank(appId, redirect)) {
            return result(HttpStatus.BAD_REQUEST, null, "回调地址与配置不符", null);
        }
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
     * @param token     令牌
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity authingUserPermission(String token) {
        try {
            DecodedJWT decode = JWT.decode(authingUtil.rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            // 获取用户
            User user = authingManagerDao.getUserByUserId(userId);
            String photo = user.getPhoto();
            String username = user.getUsername();
            String email = user.getEmail();
            String phone = user.getPhone();
            String oneidPrivacyVersionAccept = authingUserDao.getPrivacyVersionWithCommunity(
                    user.getGivenName());
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", photo);
            userData.put("username", username);
            userData.put("email", email);
            userData.put("phone", phone);
            userData.put("phone_exist", StringUtils.isNotBlank(phone));
            userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
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
        String userId = "";
        try {
            String redirectUri = servletRequest.getHeader("Referer");
            String headerToken = servletRequest.getHeader("token");
            String shaToken = CommonUtil.encryptSha256(headerToken, tokenSalt);
            String idTokenKey = "idToken_" + shaToken;
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            userId = decode.getAudience().get(0);
            String appId = decode.getClaim("client_id").asString();
            // 验证回调是否匹配
            ResponseEntity responseEntity = logoutRedirectUrisMatch(appId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200) {
                LogUtil.createLogs(userId, "logout", "login",
                        "The user logout", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
                return result(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);
            }
            String idToken = (String) redisDao.get(idTokenKey);
            if (StringUtils.isNotBlank(idToken)) {
                String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER)
                        .append(userId).toString();
                removeOnlineUser(loginKey, idToken);
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
            Boolean isLogout = authingManagerDao.kickUser(userId);
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("is_logout", isLogout);
            userData.put("client_id", appId);
            userData.put("redirect_uri", redirectUri);
            userData.put("id_token", encryptionService.decrypt(idToken));
            LogUtil.createLogs(userId, "logout", "login",
                    "The user logout", ClientIPUtil.getClientIpAddress(servletRequest), "success");
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            LogUtil.createLogs(userId, "logout", "login",
                    "The user logout", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    private void removeOnlineUser(String loginKey, String idToken) {
        try {
            List<String> userList = redisDao.getListValue(loginKey);
            if (CollectionUtils.isEmpty(userList)) {
                return;
            }
            for (String userJson : userList) {
                OnlineUserInfo onlineUserInfo = new OnlineUserInfo();
                if (userJson.startsWith("{")) {
                    onlineUserInfo = objectMapper.readValue(userJson, OnlineUserInfo.class);
                } else {
                    onlineUserInfo.setIdToken(userJson);
                }
                if (StringUtils.equals(idToken, onlineUserInfo.getIdToken())) {
                    logoutApps(idToken, onlineUserInfo.getLogoutUrls());
                    redisDao.removeListValue(loginKey, userJson);
                    break;
                }
            }
        } catch (JsonProcessingException e) {
            LOGGER.error("parse json failed {}", e.getMessage());
        }
    }
    private void logoutApps(String idToken, Set<String> logoutUrls) {
        if (CollectionUtils.isEmpty(logoutUrls)) {
            return;
        }
        for (String logoutUrl : logoutUrls) {
            LOGOUT_EXE.submit(() -> {
                try {
                    HttpResponse<kong.unirest.JsonNode> response = Unirest.get(logoutUrl)
                            .header("Authorization", idToken)
                            .asJson();
                    if (response.getStatus() != 200) {
                        LOGGER.error("logout app failed {} {}", logoutUrl, response.getStatus());
                    }
                } catch (Exception e) {
                    LOGGER.error("logout app failed {} {}", logoutUrl, e.getMessage());
                }
            });
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
            User user = authingManagerDao.getUserByUserId(userId);
            String photo = user.getPhoto();
            String username = user.getUsername();
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", photo);
            userData.put("username", username);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
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
            int expire = Integer.parseInt(env.getProperty("authing.token.expire.seconds",
                    Constant.DEFAULT_EXPIRE_SECOND));
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("userId", userId);
            userData.put("tokenExpireInterval", expire);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    /**
     * 申请令牌方法.
     *
     * @param httpServletRequest HTTP请求对象
     * @param servletResponse    HTTP响应对象
     * @param code               代码
     * @param permission         权限
     * @param redirectUrl        重定向URL
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity tokenApply(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse,
                                     String code, String permission, String redirectUrl) {
        String userId = "";
        try {
            if (!isPermissionParmValid(permission)) {
                return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
            }
            String appId = httpServletRequest.getParameter("client_id");
            // 校验appId
            if (authingUserDao.getAppById(appId) == null) {
                LogUtil.createLogs(userId, "user login", "login", "The user third party login",
                        ClientIPUtil.getClientIpAddress(httpServletRequest), "failed");
                return result(HttpStatus.BAD_REQUEST, null, "应用不存在", null);
            }
            // 将URL中的中文转码，因为@RequestParam会自动解码，而我们需要未解码的参数
            String url = redirectUrl;
            Matcher matcher = redirectUrlPattern.matcher(redirectUrl);
            String tmp = "";
            while (matcher.find()) {
                tmp = matcher.group();
                url = url.replaceAll(tmp, URLEncoder.encode(tmp, "UTF-8"));
            }
            // 通过code获取access_token，再通过access_token获取用户
            Map user = authingUserDao.getUserInfoByAccessToken(appId, code, url);
            if (user == null) {
                LogUtil.createLogs(userId, "user login", "login", "The user third party login",
                        ClientIPUtil.getClientIpAddress(httpServletRequest), "failed");
                return result(HttpStatus.UNAUTHORIZED, "user not found", null);
            }
            userId = user.get("sub").toString();
            String idToken = user.get("id_token").toString();
            String picture = user.get("picture").toString();
            String userName = (String) user.get("username");
            userName = resetUserName(appId, userName, userId);
            String phone = (String) user.get("phone_number");
            String email = (String) user.get("email");
            if (("openeuler".equals(instanceCommunity) || Constant.OPEN_UBMC.equals(instanceCommunity))
                    && StringUtils.isBlank(email)) {
                email = authingManagerDao.genPredefinedEmail(userId, userName);
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
            idToken = encryptionService.encrypt(idToken);
            // 生成token
            String[] tokens = jwtTokenCreateService.authingUserToken(new JwtCreatedParam(appId, userId, userName,
                permissionInfo, permission, idToken, oneidPrivacyVersionAccept, StringUtils.isNotBlank(phone)));

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
            LogUtil.createLogs(userId, "user login", "login", "The user third party login",
                    ClientIPUtil.getClientIpAddress(httpServletRequest), "success");
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            LogUtil.createLogs(userId, "user login", "login", "The user third party login",
                    ClientIPUtil.getClientIpAddress(httpServletRequest), "failed");
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    private String resetUserName(String appId, String userName, String userId)
            throws ServerErrorException, IOException {
        if (Constant.SUCCESS.equals(authingUserDao.checkUsername(appId, userName, instanceCommunity, true))) {
            return userName;
        } else {
            LOGGER.warn("username: {} is invalid, auto clean", userName);
            UpdateUserInput updateUserInput = new UpdateUserInput();
            updateUserInput.withUsername("");
            authingManagerDao.updateUserInfo(userId, updateUserInput);
            return "";
        }
    }

    /**
     * 发送验证码方法.
     *
     * @param request HTTP 请求对象
     * @param token     认证令牌
     * @param account   账号
     * @param channel   通道
     * @param isSuccess 是否成功标识
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity sendCode(HttpServletRequest request, String token, String account,
                                   String channel, boolean isSuccess) {
        // 图片验证码二次校验
        if (!isSuccess) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0002.getMsgZh(), null);
        }
        if (StringUtils.isAnyBlank(account, channel, token)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        if (!Constant.AUTHING_CHANNELS.contains(channel.toUpperCase(Locale.ROOT))) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        account = getAbsoluteAccount(account);
        String msg;
        String accountType = getAccountType(account);
        if (!accountType.equals("email") && !accountType.equals("phone")) {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
            LogUtil.createLogs("anonymous", "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(request), "failed");
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
        }
        // 限制1分钟只能发送一次
        String redisKey = account.toLowerCase() + "_sendcode";
        String codeOld = (String) redisDao.get(redisKey);
        if (codeOld != null) {
            LogUtil.createLogs(account, "send code", "code",
                    "Verification code has been sent within a minute",
                    ClientIPUtil.getClientIpAddress(request), "failed");
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0009.getMsgZh(), null);
        }
        String userId = "";
        try {
            token = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String appId = decode.getClaim("client_id").asString();
            userId = decode.getAudience().get(0);
            OperateFailCounter failCounter = limitUtil.initBindFailCounter(userId);
            // 限制一小时失败次数
            if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, null);
            }
            String channelReal = convertChannel(appId, account, channel);
            User user = authingManagerDao.getUserByUserId(userId);
            String emailInDb = user.getEmail();
            if (accountType.equals("email")
                    && StringUtils.isNotBlank(emailInDb)
                    && emailInDb.endsWith(Constant.AUTO_GEN_EMAIL_SUFFIX)) {
                msg = sendSelfDistributedCode(account, accountType, "CodeBindEmail");
            } else if (accountType.equals("email")) {
                msg = authingUserDao.sendEmailCodeV3(appId, account, channelReal);
            } else if (accountType.equals("phone")) {
                msg = authingUserDao.sendPhoneCodeV3(appId, account, channelReal);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (RuntimeException e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e.getMessage());
            LogUtil.createLogs(userId, "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(request), "failed");
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);
        } catch (Exception e) {
            LogUtil.createLogs(userId, "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(request), "failed");
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);
        }
        redisDao.set(redisKey, "code", 60L);
        if (!msg.equals("success")) {
            LogUtil.createLogs(userId, "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(request), "failed");
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        } else {
            LogUtil.createLogs(userId, "send code", "code",
                    "The user sends code", ClientIPUtil.getClientIpAddress(request), "success");
            return result(HttpStatus.OK, "success", null);
        }
    }

    private String convertChannel(String appId, String account, String channel) {
        String channelUp = channel.toUpperCase(Locale.ROOT);
        try {
            if ("CHANNEL_MERGE_USER".equals(channelUp)) {
                if (!authingUserDao.isUserExists(appId, account, "phone")) {
                    channelUp = "CHANNEL_BIND_PHONE";
                } else {
                    channelUp = "CHANNEL_LOGIN";
                }
            }
        } catch (Exception e) {
            LOGGER.error("convert channel failed {}", e.getMessage());
        }
        return channelUp;
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
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String account = (String) getBodyPara(body, "account");
        String accountType = (String) getBodyPara(body, "account_type");

        // 如果请求体里没有，尝试在请求参数里获取
        if (StringUtils.isBlank(account) && StringUtils.isBlank(account) && StringUtils.isBlank(accountType)) {
            account = servletRequest.getParameter("account");
            accountType = servletRequest.getParameter("account_type");
        }

        account = getAbsoluteAccount(account);

        // 图片验证码二次校验
        if (!isSuccess) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0002.getMsgZh(), null);
        }
        if (StringUtils.isAnyBlank(account, accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00012.getMsgZh(), null);
        }
        if (!accountType.equals(getAccountType(account))) {
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00012.getMsgZh(), null);
        }
        if ("phone".equals(accountType)) {
            String phoneCountryCode = authingUserDao.getPhoneCountryCode(account);
            if (!"+86".equals(phoneCountryCode)) {
                LogUtil.createLogs(account, "send code", "code",
                        "The user sends unbind code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
            }
            account = phoneCountryCode + authingUserDao.getPurePhone(account);
        } else {
            // 目前仅支持手机号解绑
            return result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E00012.getMsgZh(), null);
        }
        String res = sendSelfDistributedCode(account, accountType, "CodeUnbind");

        if (res.equals("success")) {
            LogUtil.createLogs(account, "send code", "code",
                    "The user sends unbind code", ClientIPUtil.getClientIpAddress(servletRequest), "success");
            return result(HttpStatus.OK, "success", null);
        } else {
            LogUtil.createLogs(account, "send code", "code",
                    "The user sends unbind code", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, null, res, null);
        }
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
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String oldAccount = (String) getBodyPara(body, "oldaccount");
        String oldCode = (String) getBodyPara(body, "oldcode");
        String account = (String) getBodyPara(body, "account");

        // 如果请求体里没有，尝试在请求参数里获取
        if (StringUtils.isBlank(account) && StringUtils.isBlank(oldAccount) && StringUtils.isBlank(oldCode)) {
            account = servletRequest.getParameter("account");
            oldAccount = servletRequest.getParameter("oldAccount");
            oldCode = servletRequest.getParameter("oldCode");
        }

        account = getAbsoluteAccount(account);
        String code = (String) getBodyPara(body, "code");
        String accountType = (String) getBodyPara(body, "account_type");

        String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
        String userId = "";
        try {
            String decodeToken = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(decodeToken);
            userId = decode.getAudience().get(0);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("decode token failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        } catch (Exception e) {
            LOGGER.error("decode token failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }

        if (StringUtils.isBlank(oldAccount) || StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        if (!isCodeParmValid(oldCode) || !isCodeParmValid(code)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
        }
        if (!accountType.equals(getAccountType(oldAccount)) || !accountType.equals(getAccountType(account))) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
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
        OperateFailCounter failCounter = limitUtil.initBindFailCounter(userId);
        // 限制一小时失败次数
        if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, null);
        }
        String res = authingUserDao.updateAccount(token, oldAccount, oldCode, account, code, accountType, userIp);
        if (!"true".equals(res)) {
            limitUtil.operateFail(failCounter);
        } else {
            redisDao.remove(userId + Constant.BIND_FAILED_COUNT);
        }
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
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String account = (String) getBodyPara(body, "account");
        String code = (String) getBodyPara(body, "code");
        String accountType = (String) getBodyPara(body, "account_type");

        // 如果请求体里没有，尝试在请求参数里获取
        if (StringUtils.isBlank(account) && StringUtils.isBlank(code) && StringUtils.isBlank(accountType)) {
            account = servletRequest.getParameter("account");
            code = servletRequest.getParameter("code");
            accountType = servletRequest.getParameter("accountType");
        }

        String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        if (!accountType.equals(getAccountType(account)) || !accountType.equals("phone")) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        account = getAbsoluteAccount(account);
        String redisKeyPrefix = account;
        if ("phone".equals(accountType)) {
            String phoneCountryCode = authingUserDao.getPhoneCountryCode(account);
            account = authingUserDao.getPurePhone(account);
            redisKeyPrefix = phoneCountryCode + account;
            if (!"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
                LogUtil.createLogs(account, "unbind account", "unbind",
                        "The user unbind account", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
            }
        }
        String redisKey = redisKeyPrefix + "_CodeUnbind";
        String codeTemp = (String) redisDao.get(redisKey);
        if (codeTemp == null) {
            LogUtil.createLogs(account, "unbind account", "unbind",
                    "The user unbind account", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, null, "验证码无效或已过期", null);
        }
        if (!codeTemp.equals(code)) {
            LogUtil.createLogs(account, "unbind account", "unbind",
                    "The user unbind account", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
            return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);
        }
        String res = authingUserDao.unbindAccount(token, account, accountType, userIp);
        if (res.equals("unbind success")) {
            redisDao.remove(redisKey);
            LogUtil.createLogs(account, "unbind account", "unbind",
                    "The user unbind account", ClientIPUtil.getClientIpAddress(servletRequest), "success");
            return result(HttpStatus.OK, res, null);
        }
        LogUtil.createLogs(account, "unbind account", "unbind",
                "The user unbind account", ClientIPUtil.getClientIpAddress(servletRequest), "failed");
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
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String account = (String) getBodyPara(body, "account");
        String code = (String) getBodyPara(body, "code");
        String accountType = (String) getBodyPara(body, "account_type");

        // 如果请求体里没有，尝试在请求参数里获取
        if (StringUtils.isBlank(account) && StringUtils.isBlank(code) && StringUtils.isBlank(accountType)) {
            account = servletRequest.getParameter("account");
            code = servletRequest.getParameter("code");
            accountType = servletRequest.getParameter("account_type");
        }

        String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
        String userId = "";
        try {
            String decodeToken = authingUtil.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(decodeToken);
            userId = decode.getAudience().get(0);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("decode token failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        } catch (Exception e) {
            LOGGER.error("decode token failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        if (!isCodeParmValid(code)) {
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
        }
        account = getAbsoluteAccount(account);
        //账号格式校验
        if (!account.matches(Constant.PHONEREGEX) && !account.matches(Constant.EMAILREGEX)) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        if (!accountType.equals(getAccountType(account))) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
        }
        OperateFailCounter failCounter = limitUtil.initBindFailCounter(userId);
        // 限制一小时失败次数
        if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, null);
        }
        String res = authingUserDao.bindAccount(token, account, code, accountType, userIp);
        if (!"true".equals(res)) {
            limitUtil.operateFail(failCounter);
        } else {
            redisDao.remove(userId + Constant.BIND_FAILED_COUNT);
        }
        return message(res);
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
     * @param servletRequest 请求入参
     * @param token    令牌
     * @param platform 平台
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity unLinkAccount(HttpServletRequest servletRequest, String token, String platform) {
        if (StringUtils.isAnyBlank(token, platform)) {
            result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        String ip = ClientIPUtil.getClientIpAddress(servletRequest);
        String msg = authingUserDao.unLinkAccount(token, platform, ip);
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
        String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
        try {
            res = authingUserDao.updateUserBaseInfo(token, map, userIp);
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
        String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
        String updateResult = authingUserDao.updatePhoto(token, file, userIp);
        if (Constant.SUCCESS.equals(updateResult)) {
            return result(HttpStatus.OK, "update photo success", null);
        } else {
            return result(HttpStatus.BAD_REQUEST, null, updateResult, null);
        }
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
            if (Constant.SUCCESS.equals(msg)) {
                String token = authingUtil.rsaDecryptToken(cookie.getValue());
                DecodedJWT decode = JWT.decode(token);
                String userId = decode.getAudience().get(0);
                logoutAllSessions(userId, servletRequest, servletResponse);
                authingManagerDao.kickUser(userId);
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
            if (!isCodeParmValid(code)) {
                return result(HttpStatus.BAD_REQUEST, null, msg.toString(), null);
            }
            account = getAbsoluteAccount(account);
            // 邮箱手机号验证
            String accountType = getAccountType(account);
            if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
            }
            String userId = "";
            if (accountType.equals(Constant.EMAIL_TYPE)) {
                msg = authingUserDao.resetPwdVerifyEmail(appId, account, code);
                userId = authingManagerDao.getUserIdByEmail(account);
            } else if (accountType.equals(Constant.PHONE_TYPE)) {
                msg = authingUserDao.resetPwdVerifyPhone(appId, account, code);
                userId = authingManagerDao.getUserIdByPhone(account);
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
        } catch (Exception e) {
            LOGGER.error("verify reset password failed {}", e.getMessage());
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
            String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
            if (StringUtils.isBlank(newPwd)) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
            }
            if (!isPasswdParmValid(newPwd)) {
                LOGGER.error("password is invalid");
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
                LogUtil.createLogs(userId, "reset password", "user",
                        "The user reset password", userIp, "success");
                authingManagerDao.kickUser(userId);
            } else {
                LogUtil.createLogs(userId, "reset password", "user",
                        "The user reset password", userIp, "failed");
            }
            return resetMsg.equals(Constant.SUCCESS) ? result(HttpStatus.OK, Constant.SUCCESS, null)
                    : result(HttpStatus.BAD_REQUEST, null, resetMsg, null);
        } catch (Exception e) {
            LOGGER.error("reset password failed {}", e.getMessage());
        }
        return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00053, null, null);
    }

    /**
     * 构建响应实体方法.
     *
     * @param status  HTTP状态
     * @param msg     消息
     * @param data    数据对象
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity result(HttpStatus status, String msg, Object data) {
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
                return result(HttpStatus.OK, MessageCodeConfig.S0001, null, null);
            case "false":
                return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
            default:
                if (!res.contains(":")) {
                    return result(HttpStatus.BAD_REQUEST, null, res, null);
                }
                ObjectMapper jsonReader = new ObjectMapper();
                String message = "faild";
                try {
                    res = res.substring(Constant.AUTHING_RES_PREFIX_LENGTH);
                    Iterator<JsonNode> buckets = jsonReader.readTree(res).iterator();
                    if (buckets.hasNext()) {
                        message = buckets.next().get("message").get("message").asText();
                    }
                    message = AuthingRespConvert.convertBindEmailMsg(message);
                } catch (JsonProcessingException e) {
                    LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
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

    /**
     * 获取请求体参数对应内容.
     * @param body 请求体.
     * @param paraName 请求体参数.
     * @return 请求体参数内容.
     */
    public Object getBodyPara(Map<String, Object> body, String paraName) {
        return body.getOrDefault(paraName, null);
    }

    /**
     * 登录authing.
     *
     * @param appId 应用id
     * @param account 账号
     * @param code 验证码
     * @param password 密码
     * @param clientIp 用户IP
     * @return 登录响应体
     */
    public Object login(String appId, String account, String code, String password, String clientIp) {
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
                        ? authingUserDao.loginByEmailCode(app, account, code, clientIp)
                        : authingUserDao.loginByEmailPwd(app, account, password, clientIp);
            } else if (accountType.equals(Constant.PHONE_TYPE)) { // 手机号登录
                msg = StringUtils.isNotBlank(code)
                        ? authingUserDao.loginByPhoneCode(app, account, code, clientIp)
                        : authingUserDao.loginByPhonePwd(app, account, password, clientIp);
            } else { // 用户名登录
                // 用户名校验
                if (StringUtils.isBlank(account)) {
                    return MessageCodeConfig.E00012.getMsgZh();
                }
                msg = authingUserDao.loginByUsernamePwd(app, account, password, clientIp);
            }
        } catch (ServerErrorException e) {
            return MessageCodeConfig.E00048.getMsgZh();
        }
        return msg;
    }

    /**
     * 设置cookie.
     * @param request 请求对象.
     * @param response 响应对象.
     * @param token token.
     * @param verifyToken verifyToken.
     */
    public void setCookieLogged(HttpServletRequest request, HttpServletResponse response,
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
     * 合并仅有一个三方绑定的用户到手机号对应账号.
     *
     * @param servletRequest 请求体
     * @param servletResponse 响应体
     * @param token token
     * @return 合并后用户登录信息
     */
    @Override
    public ResponseEntity mergeUser(HttpServletRequest servletRequest,
                                    HttpServletResponse servletResponse, String token) {
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
            String account = (String) getBodyPara(body, "account");
            String appId = (String) getBodyPara(body, "client_id");
            if (!Constant.PHONE_TYPE.equals(getAccountType(account))) {
                return result(HttpStatus.BAD_REQUEST, null, "", null);
            }
            if (!authingUserDao.isUserExists(appId, account, "phone")) {
                return bindAccount(servletRequest, servletResponse, token);
            } else {
                return mergeExistUser(servletRequest, servletResponse, token);
            }
        } catch (Exception e) {
            LOGGER.error("[merge users] merge users failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
    }

    private ResponseEntity mergeExistUser(HttpServletRequest servletRequest,
                                          HttpServletResponse servletResponse, String token) {
        try {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
            String appId = (String) getBodyPara(body, "client_id");
            String account = (String) getBodyPara(body, "account");
            String code = (String) getBodyPara(body, "code");
            String clientIp = ClientIPUtil.getClientIpAddress(servletRequest);
            if (!Constant.PHONE_TYPE.equals(getAccountType(account))) {
                return result(HttpStatus.BAD_REQUEST, null, "", null);
            }
            // 登录成功返回用户token
            Object loginRes = login(appId, account, code, null, clientIp);
            // 获取用户信息
            String newIdToken;
            String newUserId = "";
            User newuser = null;
            if (loginRes instanceof JSONObject) {
                JSONObject userObj = (JSONObject) loginRes;
                newIdToken = userObj.getString("id_token");
                newUserId = JWT.decode(newIdToken).getSubject();
                newuser = authingManagerDao.getUserByUserId(newUserId);
            } else if (MessageCodeConfig.E0002.getMsgZh().equals(loginRes)
                    || MessageCodeConfig.E00026.getMsgZh().equals(loginRes)) {
                return result(HttpStatus.BAD_REQUEST, null, (String) loginRes, null);
            } else {
                LOGGER.error("merge users failed {}", loginRes);
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
            }
            String currentUserId = authingUtil.getUserIdFromToken(token);
            User currentUser = authingManagerDao.getUserByUserId(currentUserId);
            if (currentUser == null) {
                LOGGER.error("user is null");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00071, null, null);
            }
            List<Identity> identities = currentUser.getIdentities();
            if (identities == null || identities.size() != 1) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00068, null, null);
            }
            Identity currentIdentity = identities.get(0);
            if (currentIdentity == null) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00069, null, null);
            }
            if (StringUtils.isAnyBlank(currentIdentity.getUserIdInIdp(), currentIdentity.getUserPoolId(),
                    currentIdentity.getExtIdpId())) {
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00069, null, null);
            }
            if (hasSameIdentityType(newuser.getIdentities(), currentIdentity)) {
                LOGGER.error("[merge users] phone user has been bind");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00070, null, null);
            }
            if (!authingManagerDao.removeIdentity(currentIdentity)) {
                LOGGER.error("[merge users] remove identity failed");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00071, null, null);
            }
            if (!authingManagerDao.bindIdentity(newUserId, currentIdentity)) {
                authingManagerDao.bindIdentity(currentUserId, currentIdentity);
                LOGGER.error("[merge users] bind identity failed");
                return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00071, null, null);
            }
            authingManagerDao.deleteUserById(currentUserId);
            // 登录成功解除登录失败次数限制
            redisDao.remove(account + Constant.LOGIN_COUNT);
            // 获取是否同意隐私
            String oneidPrivacyVersionAccept = authingUserDao.getPrivacyVersionWithCommunity(
                    newuser.getGivenName());
            // 生成token
            String userName = newuser.getUsername();
            if (Objects.isNull(userName)) {
                userName = "";
            }
            newIdToken = encryptionService.encrypt(newIdToken);
            String[] tokens = jwtTokenCreateService.authingUserToken(new JwtCreatedParam(appId, newUserId, userName,
                "", "", newIdToken, oneidPrivacyVersionAccept, StringUtils.isNotBlank(newuser.getPhone())));
            String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(newUserId).toString();
            int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
            redisDao.addList(loginKey, newIdToken, expireSeconds);
            long listSize = redisDao.getListSize(loginKey);
            if (listSize > maxLoginNum) {
                redisDao.removeListTail(loginKey, maxLoginNum);
            }
            // 写cookie
            servletResponse.reset();
            setCookieLogged(servletRequest, servletResponse, tokens[0], tokens[1]);
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", tokens[1]);
            userData.put("photo", newuser.getPhoto());
            userData.put("username", newuser.getUsername());
            userData.put("email_exist", StringUtils.isNotBlank(newuser.getEmail()));
            userData.put("phone_exist", StringUtils.isNotBlank(newuser.getPhone()));
            userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);
            LogUtil.createLogs(currentUser.getId(), "merge user", "user",
                    "The user merge to" + newUserId, clientIp, "success");
            return result(HttpStatus.OK, "success", userData);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("[merge users] merge users failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        } catch (Exception e) {
            LOGGER.error("[merge users] merge users failed {}", e.getMessage());
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
    }

    private boolean hasSameIdentityType(List<Identity> newIdentities, Identity currentIdentity) {
        if (CollectionUtils.isEmpty(newIdentities) || currentIdentity == null) {
            return false;
        }
        for (Identity identity : newIdentities) {
            if (StringUtils.equals(identity.getExtIdpId(), currentIdentity.getExtIdpId())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 多端登出所有用户.
     * @param userId
     * @param request
     * @param response
     */
    public void logoutAllSessions(String userId, HttpServletRequest request, HttpServletResponse response) {
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

    /**
     * 验证密码.
     * @param passWord 密码.
     * @return 密码合理则返回true，不合理返回false.
     */
    public boolean isPasswdParmValid(String passWord) {
        if (StringUtils.isNotBlank(passWord) && passWord.length() < 500
                && passWord.matches(Constant.NORMAL_STR_REGEX)) {
            return true;
        }
        return false;
    }

    /**
     * 验证验证码.
     * @param code 验证码.
     * @return 验证码合理则返回true，不合理返回false.
     */
    public boolean isCodeParmValid(String code) {
        if (StringUtils.isNotBlank(code) && code.length() < 10 && code.matches(Constant.NORMAL_STR_REGEX)) {
            return true;
        }
        return false;
    }

    /**
     * 验证许可.
     * @param permission 许可.
     * @return 许可合理则返回true，不合理返回false.
     */
    public boolean isPermissionParmValid(String permission) {
        if (StringUtils.isNotBlank(permission) && permission.length() < 100
                && permission.matches(Constant.NORMAL_STR_REGEX)) {
            return true;
        }
        return false;
    }

    /**
     * 验证用户名.
     * @param userName 用户名.
     * @return 用户名合理则返回true，不合理返回false.
     */
    public boolean isUserNameParmValid(String userName) {
        if (StringUtils.isBlank(userName) || userName.length() > Constant.OPEN_MIND_USERNAME_MAX) {
            return false;
        }
        return true;
    }
}
