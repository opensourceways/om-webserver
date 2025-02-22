package com.om.Service.impl;

import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.OneidDao;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdUserDao;
import com.om.Modules.LoginFailCounter;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.OneIdService;
import com.om.Service.inter.LoginServiceInter;
import com.om.Utils.CommonUtil;
import com.om.Utils.HS256Util;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.LimitUtil;
import com.om.Vo.dto.LoginParam;
import com.om.config.LoginConfig;
import kong.unirest.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@Service
@ConditionalOnProperty(value = "service.oidc", havingValue = "oidcServiceImplOneId")
public class LoginServiceImplOneId implements LoginServiceInter {

    private static final Logger logger = LoggerFactory.getLogger(LoginServiceImplOneId.class);

    private static ObjectMapper objectMapper = new ObjectMapper();

    @Value("${opengauss.pool.key}")
    private String poolId;

    @Value("${opengauss.pool.secret}")
    private String poolSecret;

    /**
     * OneID隐私版本.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

    /**
     * 社区名称.
     */
    @Value("${community}")
    private String localCommunity;

    /**
     * jenkins.opengauss需要使用白名单登录的clientId
     */
    @Value("${jenkins.opengauss.login.client.id:}")
    private String jenkinsOpenGaussWhiteLoginClientId;

    /**
     * opengaussjenkins.osinfra需要使用白名单登录的clientId
     */
    @Value("${opengaussjenkins.osinfra.login.client.id:}")
    private String openGaussJenkinsOsinfraWhiteLoginClientId;

    /**
     * jenkins.opengauss使用白名单登录时的白名单
     */
    @Value("#{'${jenkins.opengauss.login.email.white.list:}'.split(',')}")
    private List<String> jenkinsOpenGaussWhiteLoginList;

    /**
     * opengaussjenkins.osinfra使用白名单登录时的白名单
     */
    @Value("#{'${opengaussjenkins.osinfra.login.email.white.list:}'.split(',')}")
    private List<String> openGaussJenkinsOsinfraWhiteLoginList;

    @Autowired
    OneIdService oneIdService;

    @Autowired
    OneIdAppDao oneIdAppDao;

    @Autowired
    OneIdUserDao oneIdUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    LimitUtil limitUtil;

    @Autowired
    private HttpServletRequest servletRequest;

    @Autowired
    private HttpServletResponse servletResponse;

    @Autowired
    private OneidDao oneidDao;

    @Override
    public ResponseEntity<?> appVerify(String clientId, String redirectUri) {
        try {
            if (!oneIdService.verifyRedirectUri(clientId, redirectUri)) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00002, null);
            }
            return Result.resultOidc(HttpStatus.OK, MessageCodeConfig.S0001, null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
    }

    @Override
    public ResponseEntity<?> userLogin(LoginParam loginParam) {
        try {
            loginParam.setAccount(CommonUtil.getAbsoluteAccount(loginParam.getAccount()));
            LoginFailCounter failCounter = limitUtil.initLoginFailCounter(loginParam.getAccount());

            // 限制一分钟登录失败次数
            if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00030, null, limitUtil.loginFail(failCounter), null);
            }

            // 多次失败需要图片验证码
            boolean isSuccess = oneIdService.verifyCaptcha(loginParam.getCaptchaVerification());
            if (limitUtil.isNeedCaptcha(failCounter).get(Constant.NEED_CAPTCHA_VERIFICATION)) {
                if (!isSuccess) {
                    return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, limitUtil.loginFail(failCounter), null);
                }
            }

            String clientId = loginParam.getClient_id();
            String account = loginParam.getAccount();
            boolean whiteLoginCheck = true;
            // 检查该clientId是否需要通过白名单过滤
            if (StringUtils.hasText(clientId) && clientId.equals(jenkinsOpenGaussWhiteLoginClientId) && !jenkinsOpenGaussWhiteLoginList.contains(account)) {
                whiteLoginCheck = false;
            } else if (StringUtils.hasText(clientId) && clientId.equals(openGaussJenkinsOsinfraWhiteLoginClientId) && !openGaussJenkinsOsinfraWhiteLoginList.contains(account)) {
                whiteLoginCheck = false;
            }

            if (!whiteLoginCheck) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00070, null, null, null);
            }

            // app校验
            OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
            if (null == app) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00047, null, limitUtil.loginFail(failCounter), null);
            }

            // 登录
            String accountType = oneIdService.getAccountType(loginParam.getAccount());
            OneIdEntity.User user = null;
            if (!StringUtils.hasText(accountType)) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null, null);
            }

            String redisKey = loginParam.getAccount() + "_sendCode_" + loginParam.getCommunity();
            String codeTemp = (String) redisDao.get(redisKey);
            if (StringUtils.hasText(loginParam.getPassword())) {
                String password = Base64.encodeBase64String(Hex.decodeHex(loginParam.getPassword()));
                user = oneIdUserDao.loginByPassword(loginParam.getAccount(), accountType, password);
            } else {
                // 校验隐私协议
                String oneidPrivacy = loginParam.getOneidPrivacyAccepted();
                if (StringUtils.isEmpty(oneidPrivacy) || !oneidPrivacyVersion.equals(oneidPrivacy)) {
                    logger.error("oneidPrivacy param error.");
                    return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null, null);
                }
                // 验证码校验
                MessageCodeConfig messageCodeConfig = oneIdService.checkCode(loginParam.getCode(), codeTemp);

                if (messageCodeConfig != MessageCodeConfig.S0001) {
                    return Result.setResult(HttpStatus.BAD_REQUEST, messageCodeConfig, null, limitUtil.loginFail(failCounter), null);
                }

                user = oneIdUserDao.getUserInfo(loginParam.getAccount(), accountType);
                if (user == null) {
                    // 验证码登录，自动创建用户
                    user = autoCreatUser(accountType, loginParam.getAccount());
                }
            }

            if (user == null) {
                redisDao.updateValue(redisKey, codeTemp + "_used", 0);
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00027, null, limitUtil.loginFail(failCounter), null);
            }

            // 登录成功解除登录失败次数限制
            redisDao.remove(loginParam.getAccount() + Constant.LOGIN_COUNT);

            // 登录成功，验证码失效
            redisDao.updateValue(redisKey, codeTemp + "_used", 0);

            // 生成token
            String idToken = HS256Util.getHS256Token(user, loginParam.getClient_id(), app.getAppSecret());
            if (idToken == null) {
                return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
            }
            return oneIdService.loginSuccessSetToken(user, idToken, loginParam.getClient_id());
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
    }

    private OneIdEntity.User autoCreatUser(String accountType, String account) throws JsonProcessingException {
        OneIdEntity.User user = null;
        HashMap<String, Object> userInfo = new HashMap<>();
        userInfo.put(accountType, account);
        String userJsonStr = objectMapper.writeValueAsString(userInfo);
        JSONObject userObj = oneidDao.createUser(poolId, poolSecret, userJsonStr);
        if(userObj == null) {
            return user;
        }
        user = JSON.parseObject(userObj.toString(), OneIdEntity.User.class);

        return user;
    }

    @Override
    public ResponseEntity<?> userLogout(String clientId, String token) {
        try {
            // app校验
            OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
            if (null == app) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00047, null, null, null);
            }
            // user校验
            token = oneIdService.rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            OneIdEntity.User user = oneIdUserDao.getUserInfo(userId, "id");
            if (user == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00034, null, null, null);
            }
            // 退出登录，该token失效
            Date issuedAt = decode.getIssuedAt();
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, (long)LoginConfig.AUTHING_TOKEN_EXPIRE_SECONDS);

            // 从redis删除verifyToken
            String verifyToken = decode.getClaim("verifyToken").asString();

            if (!redisDao.remove(Constant.ID_TOKEN_PREFIX + verifyToken)) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00048, null, null, null);
            }
            //删除cookie
            HttpClientUtils.setCookie(servletRequest, servletResponse, LoginConfig.COOKIE_TOKEN_NAME, null, true, 0, "/", LoginConfig.DOMAIN_TO_SECURE);

            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, null, null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null, null, null);
        }
    }

    @Override
    public ResponseEntity<?> refreshUser(String clientId, String token) {
        try {
            // app校验
            OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
            if (null == app) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00047, null, null, null);
            }

            // 获取用户
            DecodedJWT decode = JWT.decode(oneIdService.rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            OneIdEntity.User user = oneIdUserDao.getUserInfo(userId, "id");
            if (user == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00034, null, null, null);
            }
            String oneidPrivacyVersionAccept = CommonUtil.getPrivacyVersionWithCommunity(localCommunity,
                    user.getPrivacyVersion());
            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", user.getPhoto());
            userData.put("username", user.getUsername());
            userData.put("company", user.getCompany());
            userData.put("oneidPrivacyAccepted", oneidPrivacyVersionAccept);

            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userData, null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null, null, null);
        }
    }

    @Override
    public ResponseEntity<?> personalCenterUserInfo(String clientId, String token) {
        try {
            if (!StringUtils.hasText(clientId) || !StringUtils.hasText(token)) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00012, null, null, null);
            }
            OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
            if (app == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00042, null, null, null);
            }

            DecodedJWT decode = JWT.decode(oneIdService.rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            OneIdEntity.User user = oneIdUserDao.getUserInfo(userId, "id");

            HashMap<String, Object> userData = new HashMap<>();
            userData.put("username", user.getUsername());
            userData.put("email", user.getEmail());
            userData.put("phone", user.getPhone());
            userData.put("signedUp", user.getCreateAt());
            userData.put("nickname", user.getNickname());
            userData.put("company", user.getCompany());
            userData.put("photo", user.getPhoto());
            userData.put("identities", user.getIdentities());

            // 返回结果
            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userData, null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00012, null, null, null);
        }
    }
}
