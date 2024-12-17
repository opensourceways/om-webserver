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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.om.dao.AuthingUserDao;
import com.om.dao.RedisDao;
import com.om.modules.MessageCodeConfig;
import com.om.modules.OperateFailCounter;
import com.om.modules.ServerErrorException;
import com.om.result.Constant;
import com.om.utils.ClientIPUtil;
import com.om.utils.EncryptionService;
import com.om.utils.HttpClientUtils;
import com.om.utils.LimitUtil;
import com.om.utils.LogUtil;

import cn.authing.core.types.Application;
import cn.authing.core.types.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kong.unirest.json.JSONObject;

@Service
public class LoginService {
    /**
     * 使用 @Autowired 注解注入 AuthingService.
     */
    @Autowired
    private AuthingService authingService;

    /**
     * 使用 @Autowired 注解注入 LimitUtil.
     */
    @Autowired
    private LimitUtil limitUtil;

    /**
     * 用户最大登录数量.
     */
    @Value("${cookie.user.login.maxNum:5}")
    private Integer maxLoginNum;

    /**
     * OneID隐私版本信息.
     */
    @Value("${oneid.privacy.version: }")
    private String oneidPrivacyVersion;

    /**
     * 使用 @Autowired 注解注入 JwtTokenCreateService.
     */
    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    /**
     * 静态变量: LOGGER - 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginService.class);

    /**
     * 使用 @Autowired 注解注入 AuthingUserDao.
     */
    @Autowired
    private AuthingUserDao authingUserDao;

    /**
     * 注入加密服务.
     */
    @Autowired
    private EncryptionService encryptionService;

    /**
     * 使用 @Autowired 注解注入 RedisDao.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 注入隐私操作类.
     */
    @Autowired
    private PrivacyHistoryService privacyHistoryService;

    /**
     * 使用 @Autowired 注解注入环境变量.
     */
    @Autowired
    private Environment env;

    /**
     * 登录方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity login(HttpServletRequest servletRequest,
                                HttpServletResponse servletResponse, boolean isSuccess) {
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
        String appId = (String) authingService.getBodyPara(body, "client_id");
        String permission = (String) authingService.getBodyPara(body, "permission");
        String account = (String) authingService.getBodyPara(body, "account");
        String code = (String) authingService.getBodyPara(body, "code");
        String password = (String) authingService.getBodyPara(body, "password");
        String oneidPrivacy = (String) authingService.getBodyPara(body, "oneidPrivacyAccepted");
        String ip = ClientIPUtil.getClientIpAddress(servletRequest);
        account = authingService.getAbsoluteAccount(account);
        if (!authingService.isPermissionParmValid(permission) || StringUtils.isBlank(account)) {
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        OperateFailCounter failCounter = limitUtil.initLoginFailCounter(account);
        // 限制一小时登录失败次数
        if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
            LogUtil.createLogs("anonymous", "user login", "login",
                    "The user login", ip, "failed");
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, null);
        }
        // 多次失败需要图片验证码
        if (limitUtil.isNeedCaptcha(failCounter).get(Constant.NEED_CAPTCHA_VERIFICATION) && !isSuccess) {
            LogUtil.createLogs("anonymous", "user login", "login",
                    "The user login", ip, "failed");
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null,
                    limitUtil.loginFail(failCounter));
        }
        String accountType = authingService.getAccountType(account);
        if (!Constant.EMAIL_TYPE.equals(accountType) && !Constant.PHONE_TYPE.equals(accountType)
                && !authingService.isUserNameParmValid(account)) {
            // 用户名不符合规则，不记录，防止日志注入
            LOGGER.error("user name invalid");
            LogUtil.createLogs("anonymous", "user login", "login",
                    "The user login", ip, "failed");
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00052, null,
                    limitUtil.loginFail(failCounter));
        }
        if (StringUtils.isNotBlank(password)) {
            if (!authingService.isPasswdParmValid(password)) {
                LogUtil.createLogs(account, "user login", "login",
                        "The user login", ip, "failed");
                return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00052, null,
                        limitUtil.loginFail(failCounter));
            }
            // 压缩密码
            try {
                password = org.apache.commons.codec.binary.Base64.encodeBase64String(Hex.decodeHex(password));
            } catch (Exception e) {
                LOGGER.error("Hex to Base64 fail. " + e.getMessage());
                return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
            }
        }
        // 登录成功返回用户token
        Object loginRes = login(appId, account, code, password, oneidPrivacy);
        // 获取用户信息
        String idToken;
        String userId;
        User user;
        // 判断传入隐私版本号合法
        if (MessageCodeConfig.E00037.getMsgZh().equals(loginRes)) {
            LogUtil.createLogs(account, "user login", "login",
                    "The user login", ip, "failed");
            return authingService.result(HttpStatus.UNAUTHORIZED, MessageCodeConfig.E00037, null,
                    limitUtil.loginFail(failCounter));
        }
        if (loginRes instanceof JSONObject) {
            JSONObject userObj = (JSONObject) loginRes;
            idToken = userObj.getString("id_token");
            userId = JWT.decode(idToken).getSubject();
            user = authingUserDao.getUser(userId);
        } else {
            LogUtil.createLogs(account, "user login", "login",
                    "The user login", ip, "failed");
            return authingService.result(HttpStatus.BAD_REQUEST, null, (String) loginRes,
                    limitUtil.loginFail(failCounter));
        }
        // 登录成功解除登录失败次数限制
        redisDao.remove(account + Constant.LOGIN_COUNT);
        // 资源权限
        String permissionInfo = env.getProperty(Constant.ONEID_VERSION_V1 + "." + permission, "");
        // 获取是否同意隐私
        String oneidPrivacyVersionAccept = authingUserDao.getPrivacyVersionWithCommunity(
                user.getGivenName());
        // 同意隐私版本更新为前端传入的最新版本
        if (!oneidPrivacyVersionAccept.equals(oneidPrivacy)) {
            if (privacyHistoryService.updatePrivacy(userId, oneidPrivacy)) {
                oneidPrivacyVersionAccept = oneidPrivacy;
            }
        }

        // 生成token
        String userName = user.getUsername();
        if (Objects.isNull(userName)) {
            userName = "";
        }
        try {
            idToken = encryptionService.encrypt(idToken);
        } catch (Exception e) {
            LOGGER.error("encry id_token failed {}", e.getMessage());
            LogUtil.createLogs(account, "user login", "login",
                    "The user login", ip, "failed");
            // 服务内部异常，不算作用户认证失败次数
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
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
        authingService.setCookieLogged(servletRequest, servletResponse, tokens[0], tokens[1]);
        // 返回结果
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", tokens[1]);
        userData.put("photo", user.getPhoto());
        userData.put("username", user.getUsername());
        userData.put("email_exist", StringUtils.isNotBlank(user.getEmail()));
        userData.put("phone_exist", StringUtils.isNotBlank(user.getPhone()));
        userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);
        LogUtil.createLogs(userId, "user login", "login",
                "The user login", ip, "success");
        return authingService.result(HttpStatus.OK, "success", userData);
    }

    /**
     * 登录authing.
     *
     * @param appId 应用id
     * @param account 账号
     * @param code 验证码
     * @param password 密码
     * @param oneidPrivacy 隐私版本
     * @return 登录响应体
     */
    public Object login(String appId, String account, String code, String password, String oneidPrivacy) {
        // code/password 同时传入报错
        if ((StringUtils.isNotBlank(code) && StringUtils.isNotBlank(password))) {
            return MessageCodeConfig.E00012.getMsgZh();
        }
        // 手机 or 邮箱判断
        String accountType = "";
        if (StringUtils.isNotBlank(account)) {
            accountType = authingService.getAccountType(account);
        }
        if (StringUtils.isNotBlank(code)
                && (Constant.EMAIL_TYPE.equals(accountType) || Constant.PHONE_TYPE.equals(accountType))) {
            // 校验隐私协议
            if (StringUtils.isEmpty(oneidPrivacy) || !oneidPrivacyVersion.equals(oneidPrivacy)) {
                return MessageCodeConfig.E00037.getMsgZh();
            }
            if (!authingService.isCodeParmValid(code)) {
                return MessageCodeConfig.E0002.getMsgZh();
            }
        }
        if (Constant.PHONE_TYPE.equals(accountType) && !"+86".equals(authingUserDao.getPhoneCountryCode(account))) {
            return MessageCodeConfig.E00068.getMsgEn();
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
                if (!authingService.isUserNameParmValid(account)) {
                    return MessageCodeConfig.E00052.getMsgZh();
                }
                msg = authingUserDao.loginByUsernamePwd(app, account, password);
            }
        } catch (ServerErrorException e) {
            return MessageCodeConfig.E00048.getMsgZh();
        }

        return msg;
    }
}
