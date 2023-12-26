package com.om.Service.impl;

import com.alibaba.fastjson.JSON;
import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdUserDao;
import com.om.Modules.LoginFailCounter;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.JwtTokenCreateService;
import com.om.Service.inter.OidcServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.LimitUtil;
import com.om.Utils.RSAUtil;
import com.om.Vo.dto.LoginParam;
import com.om.Vo.dto.OidcAuth;
import com.om.Vo.dto.OidcAuthorize;
import com.om.Vo.dto.OidcToken;
import com.om.config.LoginConfig;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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

@Service
@ConditionalOnProperty(value = "service.oidc", havingValue = "oidcServiceImplOneId")
public class OidcServiceImplOneId implements OidcServiceInter {

    private static final Logger logger = LoggerFactory.getLogger(OidcServiceImplOneId.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    OneIdAppDao oneIdAppDao;

    @Autowired
    OneIdUserDao oneIdUserDao;

    @Autowired
    LimitUtil limitUtil;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    @Autowired
    RedisDao redisDao;

    @Autowired
    private CaptchaService captchaService;


    @Autowired
    private HttpServletRequest servletRequest;

    @Autowired
    private HttpServletResponse servletResponse;

    @Override
    public ResponseEntity<?> oidcAuthorize(OidcAuthorize oidcAuthorize) {
        try {
            if (!Constant.RESPONSE_TYPE_AVAILABLE.contains(oidcAuthorize.getResponse_type())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00001, null);
            }

            if (!verifyRedirectUri(oidcAuthorize.getClient_id(), oidcAuthorize.getRedirect_uri())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00002, null);
            }

            if (!StringUtils.hasText(oidcAuthorize.getScope())) {
                oidcAuthorize.setScope("openid profile");
            } else {
                List<String> scopeList = Arrays.asList(oidcAuthorize.getScope().split("\\s+"));
                if (!scopeList.contains("openid") || !scopeList.contains("profile")) {
                    return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00003, null);
                }
                for (String s : scopeList) {
                    if (!Constant.SCOPE_AVAILABLE.contains(s)) {
                        return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00004, null);
                    }
                }
            }

            if (!StringUtils.hasText(oidcAuthorize.getState())) {
                oidcAuthorize.setState(UUID.randomUUID().toString().replaceAll("-", ""));
            }

            // 重定向到登录页
            String loginPage = LoginConfig.OIDC_LOGIN_PAGE;
            if ("register".equals(oidcAuthorize.getEntity())) {
                loginPage = LoginConfig.OIDC_REGISTER_PAGE;
            }
            String loginPageRedirect = String.format("%s?client_id=%s&scope=%s&redirect_uri=%s&response_mode=query&state=%s",
                    loginPage,
                    oidcAuthorize.getClient_id(),
                    oidcAuthorize.getScope(),
                    oidcAuthorize.getRedirect_uri(),
                    oidcAuthorize.getState());

            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).header(HttpHeaders.LOCATION, loginPageRedirect).build();
        } catch (Exception e) {
            e.printStackTrace();
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
    }

    @Override
    public ResponseEntity<?> oidcAuth(String token, OidcAuth oidcAuth) {
        try {
            if (!Constant.RESPONSE_TYPE_AVAILABLE.contains(oidcAuth.getResponse_type())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00001, null);
            }

            if (!verifyRedirectUri(oidcAuth.getClient_id(), oidcAuth.getRedirect_uri())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00002, null);
            }

            if (!StringUtils.hasText(oidcAuth.getScope())) {
                oidcAuth.setScope("openid profile");
            } else {
                List<String> scopeList = Arrays.asList(oidcAuth.getScope().split("\\s+"));
                if (!scopeList.contains("openid") || !scopeList.contains("profile")) {
                    return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00003, null);
                }
                for (String s : scopeList) {
                    if (!Constant.SCOPE_AVAILABLE.contains(s)) {
                        return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00004, null);
                    }
                }
            }

            if (!StringUtils.hasText(oidcAuth.getState())) {
                oidcAuth.setState(UUID.randomUUID().toString().replaceAll("-", ""));
            }

            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            String headToken = decode.getClaim("verifyToken").asString();
            String idToken = (String) redisDao.get("idToken_" + headToken);


            String accessToken = jwtTokenCreateService.oidcToken(userId, Constant.OIDCISSUER, oidcAuth.getScope(), LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE, null);
            String refreshToken = jwtTokenCreateService.oidcToken(userId, Constant.OIDCISSUER, oidcAuth.getScope(), LoginConfig.OIDC_REFRESH_TOKEN_EXPIRE, null);

            String code = CodeUtil.randomStrBuilder(32);

            HashMap<String, String> codeMap = new HashMap<>();
            codeMap.put("accessToken", accessToken);
            codeMap.put("refreshToken", refreshToken);
            codeMap.put("idToken", idToken);
            codeMap.put("appId", oidcAuth.getClient_id());
            codeMap.put("redirectUri", oidcAuth.getRedirect_uri());
            codeMap.put("scope", oidcAuth.getScope());
            String codeMapStr = "oidcCode:" + objectMapper.writeValueAsString(codeMap);
            redisDao.set(code, codeMapStr, LoginConfig.OIDC_CODE_EXPIRE);

            HashMap<String, String> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessToken);
            userTokenMap.put("refresh_token", refreshToken);
            userTokenMap.put("idToken", idToken);
            userTokenMap.put("scope", oidcAuth.getScope());
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes()), userTokenMapStr, LoginConfig.OIDC_REFRESH_TOKEN_EXPIRE);

            String res = String.format("%s?code=%s&state=%s", oidcAuth.getRedirect_uri(), code, oidcAuth.getState());
            return Result.resultOidc(HttpStatus.OK, MessageCodeConfig.OIDC_S00001, res);
        } catch (Exception e) {
            e.printStackTrace();
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
    }

    @Override
    public ResponseEntity<?> oidcToken(OidcToken oidcToken) {
        try {
            String grantType = oidcToken.getGrant_type();
            if (grantType.equals("authorization_code")) {
                String appId = oidcToken.getClient_id();
                String appSecret = oidcToken.getClient_secret();
                String redirectUri = oidcToken.getRedirect_uri();
                String code = oidcToken.getCode();
                return getOidcTokenByCode(appId, appSecret, code, redirectUri);
            } else if (grantType.equals("password")) {
                String appId = oidcToken.getClient_id();
                String appSecret = oidcToken.getClient_secret();
                String redirectUri = oidcToken.getRedirect_uri();
                String account = oidcToken.getAccount();
                String password = oidcToken.getPassword();
                String scope = oidcToken.getScope();
                return getOidcTokenByPassword(appId, appSecret, account, password, redirectUri, scope);
            } else if (grantType.equals("refresh_token")) {
                String refreshToken = oidcToken.getRefresh_token();
                return oidcRefreshToken(refreshToken);
            } else {
                return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00006, null);
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            redisDao.remove("code");
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
    }

    @Override
    public ResponseEntity<?> oidcUser(String token) {
        try {
            if (!StringUtils.hasText(token)) {
                return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00007, null);
            }
            String accessToken = token.replace("Bearer ", "");

            // 解析access_token
            String decryptedToken = rsaDecryptToken(accessToken);
            DecodedJWT decode = JWT.decode(decryptedToken);
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();

            // token是否被刷新了或者已经过期
            Object refreshedToken = redisDao.get(DigestUtils.md5DigestAsHex(accessToken.getBytes()));
            if (refreshedToken != null || expiresAt.before(new Date())) {
                return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00007, null);
            }
            JSONObject userObj = oneIdUserDao.getUserInfoToObj(userId, "id");

            // 根据scope获取用户信息 oidcScopeAuthingMapping(临时,字段映射)
            HashMap<String, Object> userData = new HashMap<>();
            HashMap<String, Object> addressMap = new HashMap<>();

            // 1、默认字段
            for (String profile : LoginConfig.OIDC_SCOPE_PROFILE) {
                String profileTemp = oidcScopeAuthingMapping().getOrDefault(profile, profile);
                Object value = jsonObjObjectValue(userObj, profileTemp);
                if ("updated_at".equals(profile) && value != null) {
                    DateTimeFormatter df = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    value = LocalDateTime.parse(value.toString(), df).toInstant(ZoneOffset.UTC).toEpochMilli();
                }
                userData.put(profile, value);
            }

            // 2、指定字段
            String[] scopes = decode.getClaim("scope").asString().split(" ");
            for (String scope : scopes) {
                if (scope.equals("openid") || scope.equals("profile")) continue;
                String[] claims = oidcScopeOthers().getOrDefault(scope, new String[]{scope});
                for (String claim : claims) {
                    String profileTemp = oidcScopeAuthingMapping().getOrDefault(claim, claim);
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
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }
    }

    @Override
    public ResponseEntity<?> appVerify(String clientId, String redirectUri) {
        try {
            if (!verifyRedirectUri(clientId, redirectUri)) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00002, null);
            }
            return Result.resultOidc(HttpStatus.OK, MessageCodeConfig.OIDC_S00001, null);
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
            boolean isSuccess = verifyCaptcha(loginParam.getCaptchaVerification());
            if (limitUtil.isNeedCaptcha(failCounter).get(Constant.NEED_CAPTCHA_VERIFICATION)) {
                if (!isSuccess) {
                    return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E0002, null, limitUtil.loginFail(failCounter), null);
                }
            }

            // app校验
            OneIdEntity.App app = oneIdAppDao.getAppInfo(loginParam.getClient_id());
            if (null == app) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00047, null,limitUtil.loginFail(failCounter), null);
            }

            // 登录
            String accountType = getAccountType(loginParam.getAccount());
            OneIdEntity.User user = null;
            if (!StringUtils.hasText(accountType)) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null,null, null);
            }

            String redisKey = loginParam.getAccount() + "_sendCode_" + loginParam.getCommunity();
            String codeTemp = (String) redisDao.get(redisKey);
            if (StringUtils.hasText(loginParam.getPassword())) {
                String password = Base64.encodeBase64String(Hex.decodeHex(loginParam.getPassword()));
                user = oneIdUserDao.loginByPassword(loginParam.getAccount(), accountType, loginParam.getPassword());
            } else {
                // 验证码校验
                MessageCodeConfig messageCodeConfig = checkCode(loginParam.getCode(), codeTemp);

                if (messageCodeConfig != MessageCodeConfig.S0001) {
                    return Result.setResult(HttpStatus.BAD_REQUEST, messageCodeConfig, null,limitUtil.loginFail(failCounter), null);
                }

                user = oneIdUserDao.getUserInfo(loginParam.getAccount(), accountType);
            }

            if (user == null) {
                redisDao.updateValue(redisKey, codeTemp + "_used", 0);
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00027, null,limitUtil.loginFail(failCounter), null);
            }

            String idToken = user.getId();

            // 登录成功解除登录失败次数限制
            redisDao.remove(loginParam.getAccount() + Constant.LOGIN_COUNT);

            // 生成token
            String[] tokens = jwtTokenCreateService.authingUserToken(loginParam.getClient_id(), user.getId(), user.getUsername(), "", "", idToken);
            String token = tokens[0];
            String verifyToken = tokens[1];

            // 写cookie
            String maxAgeTemp = LoginConfig.AUTHING_COOKIE_MAX_AGE;
            int expire = LoginConfig.AUTHING_TOKEN_EXPIRE_SECONDS;
            int maxAge = expire;
            if (StringUtils.hasText(maxAgeTemp)) {
                maxAge = Integer.parseInt(maxAgeTemp);
            }

            HttpClientUtils.setCookie(servletRequest, servletResponse, LoginConfig.COOKIE_TOKEN_NAME,
                    token, true, maxAge, "/", LoginConfig.DOMAIN_TO_SECURE);
            HttpClientUtils.setCookie(servletRequest, servletResponse, LoginConfig.COOKIE_VERIFY_TOKEN_NAME,
                    verifyToken, false, expire, "/", LoginConfig.DOMAIN_TO_SECURE);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", verifyToken);
            userData.put("photo", user.getPhoto());
            userData.put("username", user.getUsername());
            userData.put("email_exist", StringUtils.hasText(user.getEmail()));
            // 登录成功，验证码失效
            redisDao.updateValue(redisKey, codeTemp + "_used", 0);
            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userData, null);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
        }

    }


    private String getAccountType(String account) {
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



    private boolean verifyCaptcha(String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        return response.isSuccess();
    }

    private HashMap<String, String> oidcScopeAuthingMapping() {
        HashMap<String, String> authingMapping = new HashMap<>();
        for (String mapping : LoginConfig.OIDC_SCOPE_AUTHING_MAPPING) {
            if (!StringUtils.hasText(mapping)) continue;
            String[] split = mapping.split(":");
            authingMapping.put(split[0], split[1]);
        }
        return authingMapping;
    }

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

    private HashMap<String, String[]> oidcScopeOthers() {
        HashMap<String, String[]> otherMap = new HashMap<>();
        for (String other : LoginConfig.OIDC_SCOPE_OTHER) {
            if (!StringUtils.hasText(other)) continue;
            String[] split = other.split("->");
            otherMap.put(split[0], split[1].split(","));
        }
        return otherMap;
    }

    public boolean verifyRedirectUri(String clientId, String redirectUri) throws Exception {
        OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
        if (! StringUtils.hasText(app.getRedirectUrls())) {
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

    private MessageCodeConfig checkCode(String code, String codeTemp) {
        if (code == null || codeTemp == null || codeTemp.endsWith("_used")) {
            return MessageCodeConfig.E0001;
        }
        if (!codeTemp.equals(code)) {
            return MessageCodeConfig.E0002;
        }
        return MessageCodeConfig.S0001;
    }

    private String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(LoginConfig.RAS_AUTHING_PRIVATE_KEY);
        return RSAUtil.privateDecrypt(token, privateKey);
    }

    private ResponseEntity<?> getOidcTokenByCode(String appId, String appSecret, String code, String redirectUri) throws Exception {
        // 参数校验
        if (!StringUtils.hasText(appId) || !StringUtils.hasText(appSecret))
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00008, null);
        // 用户code获取token必须包含code、redirectUri
        if (!StringUtils.hasText(code) || !StringUtils.hasText(redirectUri))
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00009, null);

        // 授权码校验
        String codeMapStr = (String) redisDao.get(code);
        if (!StringUtils.hasText(codeMapStr))
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00010, null);

        // 授权码信息
        com.fasterxml.jackson.databind.JsonNode jsonNode = objectMapper.readTree(codeMapStr.replace("oidcCode:", ""));
        String appIdTemp = jsonNode.get("appId").asText();
        String redirectUriTemp = jsonNode.get("redirectUri").asText();
        String scopeTemp = jsonNode.get("scope").asText();

        // app校验（授权码对应的app）
        if (!appId.equals(appIdTemp)) {
            redisDao.remove(code);
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00010, null);
        }

        // app回调地址校验（授权码对应的app的回调地址）
        if (!redirectUri.equals(redirectUriTemp)) {
            redisDao.remove(code);
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00010, null);
        }

        // app密码校验
        OneIdEntity.App app = oneIdAppDao.verifyAppSecret(appId, appSecret);
        if (app == null) {
            redisDao.remove(code);
            return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00010, null);
        }

        HashMap<String, Object> tokens = new HashMap<>();
        tokens.put("access_token", jsonNode.get("accessToken").asText());
        tokens.put("scope", scopeTemp);
        tokens.put("expires_in", LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE);
        tokens.put("token_type", "Bearer");
        List<String> scopes = Arrays.asList(scopeTemp.split(" "));
        if (scopes.contains("offline_access")) {
            tokens.put("refresh_token", jsonNode.get("refreshToken").asText());
        }
        if (scopes.contains("id_token")) {
            tokens.put("id_token", jsonNode.get("idToken").asText());
        }

        redisDao.remove(code);
        return new ResponseEntity<>(JSON.parseObject(HtmlUtils.htmlUnescape(JSON.toJSONString(tokens)), HashMap.class), HttpStatus.OK);
    }

    private ResponseEntity<?> getOidcTokenByPassword(String appId, String appSecret, String account, String password, String redirectUri, String scope) throws Exception {
        // 参数校验
        if (!StringUtils.hasText(appId) || !StringUtils.hasText(appSecret))
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00008, null);

        if (!StringUtils.hasText(password) || !StringUtils.hasText(redirectUri))
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00011, null);

        scope = !StringUtils.hasText(scope) ? "openid profile" : scope;

        // app密码校验
        OneIdEntity.App app = oneIdAppDao.verifyAppSecret(appId, appSecret);
        if (app == null) {
            return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00012, null);
        }

        // 限制一分钟登录失败次数
        String loginErrorCountKey = account + "loginCount";
        Object v = redisDao.get(loginErrorCountKey);
        int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
        if (loginErrorCount >= LoginConfig.LOGIN_ERROR_LIMIT_COUNT) {
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00013, null);
        }

        // 用户密码校验
        OneIdEntity.User user = oneIdUserDao.loginByPassword(account, getAccountType(account), password);

        // 获取用户信息
        String idToken;
        String userId;
        if (user != null) {
            idToken = user.getId();
            userId = JWT.decode(idToken).getSubject();
        } else {
            long codeExpire = LoginConfig.MAIL_CODE_EXPIRE;
            loginErrorCount += 1;
            redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00014, null);
        }

        redisDao.remove(loginErrorCountKey);

        String accessToken = jwtTokenCreateService.oidcToken(userId, Constant.OIDCISSUER, scope, LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE, null);
        String refreshToken = jwtTokenCreateService.oidcToken(userId, Constant.OIDCISSUER, scope, LoginConfig.OIDC_REFRESH_TOKEN_EXPIRE, null);

        long expire = LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE;

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

        // 缓存 oidcRefreshToken
        String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(tokens);
        redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes()), userTokenMapStr, LoginConfig.OIDC_REFRESH_TOKEN_EXPIRE);

        return new ResponseEntity<>(JSON.parseObject(HtmlUtils.htmlUnescape(JSON.toJSONString(tokens)), HashMap.class), HttpStatus.OK);
    }

    private ResponseEntity<?> oidcRefreshToken(String refreshToken) throws Exception {
        if (!StringUtils.hasText(refreshToken))
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00015, null);

        // 解析refresh_token
        String token = rsaDecryptToken(refreshToken);
        DecodedJWT decode = JWT.decode(token);
        String userId = decode.getAudience().get(0);
        Date expiresAt = decode.getExpiresAt();

        // tokens校验
        String refreshTokenKey = DigestUtils.md5DigestAsHex(refreshToken.getBytes());
        String tokenStr = (String) redisDao.get(refreshTokenKey);
        if (!StringUtils.hasText(tokenStr)) {
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00016, null);
        }
        // refresh_token是否过期
        if (expiresAt.before(new Date())) {
            return Result.resultOidc(HttpStatus.BAD_REQUEST, MessageCodeConfig.OIDC_E00016, null);
        }

        com.fasterxml.jackson.databind.JsonNode jsonNode = objectMapper.readTree(tokenStr.replace("oidcTokens:", ""));
        String scope = jsonNode.get("scope").asText();
        String accessToken = jsonNode.get("access_token").asText();
        // 生成新的accessToken和refreshToken
        long accessTokenExpire = LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE;
        long refreshTokenExpire = LoginConfig.OIDC_REFRESH_TOKEN_EXPIRE;
        String accessTokenNew = jwtTokenCreateService.oidcToken(userId, Constant.OIDCISSUER, scope, accessTokenExpire, null);
        String refreshTokenNew = jwtTokenCreateService.oidcToken(userId, Constant.OIDCISSUER, scope, refreshTokenExpire, expiresAt);

        // 缓存新的accessToken和refreshToken
        long expire = LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE;
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

        return new ResponseEntity<>(JSON.parseObject(HtmlUtils.htmlUnescape(JSON.toJSONString(userTokenMap)), HashMap.class), HttpStatus.OK);
    }


}