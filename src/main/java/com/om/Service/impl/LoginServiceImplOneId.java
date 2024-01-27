package com.om.Service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdUserDao;
import com.om.Modules.LoginFailCounter;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.JwtTokenCreateService;
import com.om.Service.OneIdService;
import com.om.Service.inter.LoginServiceInter;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.LimitUtil;
import com.om.Vo.dto.LoginParam;
import com.om.config.LoginConfig;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@ConditionalOnProperty(value = "service.oidc", havingValue = "oidcServiceImplOneId")
public class LoginServiceImplOneId implements LoginServiceInter {

    private static final Logger logger = LoggerFactory.getLogger(LoginServiceImplOneId.class);

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
    JwtTokenCreateService jwtTokenCreateService;


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

            // app校验
            OneIdEntity.App app = oneIdAppDao.getAppInfo(loginParam.getClient_id());
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
                // 验证码校验
                MessageCodeConfig messageCodeConfig = oneIdService.checkCode(loginParam.getCode(), codeTemp);

                if (messageCodeConfig != MessageCodeConfig.S0001) {
                    return Result.setResult(HttpStatus.BAD_REQUEST, messageCodeConfig, null, limitUtil.loginFail(failCounter), null);
                }

                user = oneIdUserDao.getUserInfo(loginParam.getAccount(), accountType);
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
            String idToken = user.getId();
            return oneIdService.loginSuccessSetToken(user, idToken, loginParam.getClient_id());
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
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

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", user.getPhoto());
            userData.put("username", user.getUsername());

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

            // 返回结果
            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userData, null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00012, null, null, null);
        }
    }
}
