package com.om.Service;

import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import com.om.config.LoginConfig;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.NoSuchPaddingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class OneIdService {
    private static final Logger logger = LoggerFactory.getLogger(OneIdService.class);

    @Autowired
    private CaptchaService captchaService;

    @Autowired
    private HttpServletRequest servletRequest;

    @Autowired
    private HttpServletResponse servletResponse;

    @Autowired
    private RedisDao redisDao;

    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    @Autowired
    OneIdAppDao oneIdAppDao;

    public String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(LoginConfig.RAS_AUTHING_PRIVATE_KEY);
        return RSAUtil.privateDecrypt(token, privateKey);
    }

    public boolean verifyCaptcha(String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        return response.isSuccess();
    }

    public String getAccountType(String account) {
        if (!StringUtils.hasText(account)) {
            return "";
        }
        if (account.matches(Constant.EMAILREGEX)) {
            return "email";
        }
        if (account.matches(Constant.PHONEREGEX)) {
            return "phone";
        }
        return "username";
    }

    public MessageCodeConfig checkCode(String code, String codeTemp) {
        if (code == null || codeTemp == null || codeTemp.endsWith("_used")) {
            return MessageCodeConfig.E0001;
        }
        if (!codeTemp.equals(code)) {
            return MessageCodeConfig.E0002;
        }
        return MessageCodeConfig.S0001;
    }

    public boolean verifyRedirectUri(String clientId, String redirectUri) throws Exception {
        OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
        if (!StringUtils.hasText(app.getRedirectUrls())) {
            return false;
        }
        String[] appRedirectUriList = app.getRedirectUrls().replaceAll("\\s", "").split(",");

        for (String s : appRedirectUriList) {
            if (s.contains("*")) {
                String patternString = s.replace("*", ".*");

                Pattern pattern = Pattern.compile(patternString);

                Matcher matcher = pattern.matcher(redirectUri);

                if (matcher.matches()) {
                    return true;
                }
            } else {
                if (s.equals(redirectUri)) {
                    return true;
                }
            }
        }

        return false;
    }

    public HashMap<String, String> oidcScopeAuthingMapping() {
        HashMap<String, String> authingMapping = new HashMap<>();
        for (String mapping : LoginConfig.OIDC_SCOPE_AUTHING_MAPPING) {
            if (!StringUtils.hasText(mapping)) continue;
            String[] split = mapping.split(":");
            authingMapping.put(split[0], split[1]);
        }
        return authingMapping;
    }

    public Object jsonObjObjectValue(JSONObject jsonObj, String nodeName) {
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

    public ResponseEntity<?> loginSuccessSetToken(OneIdEntity.User user, String idToken, String appId) {
        // 生成token
        Map<String, String> tokens = jwtTokenCreateService.authingUserToken(appId, user.getId(), user.getUsername(), "", "", idToken);
        String token = tokens.get(Constant.TOKEN_Y_G_);
        String verifyToken = tokens.get(Constant.TOKEN_U_T_);

        int expire = LoginConfig.AUTHING_TOKEN_EXPIRE_SECONDS;
        int maxAge = LoginConfig.AUTHING_COOKIE_MAX_AGE;

        HttpClientUtils.setCookie(servletRequest, servletResponse, LoginConfig.COOKIE_TOKEN_NAME,
                token, true, maxAge, "/", LoginConfig.DOMAIN_TO_SECURE);
        HttpClientUtils.setCookie(servletRequest, servletResponse, LoginConfig.COOKIE_VERIFY_TOKEN_NAME,
                verifyToken, false, expire, "/", LoginConfig.DOMAIN_TO_SECURE);

        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", verifyToken);
        userData.put("photo", user.getPhoto());
        userData.put("username", user.getUsername());
        userData.put("email_exist", StringUtils.hasText(user.getEmail()));

        return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userData, null);
    }

}
