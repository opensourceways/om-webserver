package com.om.Service.impl;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdUserDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.JwtTokenCreateService;
import com.om.Service.OneIdService;
import com.om.Service.inter.OidcServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.LimitUtil;
import com.om.Vo.dto.OidcAuth;
import com.om.Vo.dto.OidcAuthorize;
import com.om.Vo.dto.OidcToken;
import com.om.config.LoginConfig;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
@ConditionalOnProperty(value = "service.oidc", havingValue = "oidcServiceImplOneId")
public class OidcServiceImplOneId implements OidcServiceInter {

    private static final Logger logger = LoggerFactory.getLogger(OidcServiceImplOneId.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    OneIdService oneIdService;

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

    @Override
    public ResponseEntity<?> oidcAuthorize(OidcAuthorize oidcAuthorize) {
        try {
            if (!Constant.RESPONSE_TYPE_AVAILABLE.contains(oidcAuthorize.getResponse_type())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, MessageCodeConfig.OIDC_E00001, null);
            }

            if (!oneIdService.verifyRedirectUri(oidcAuthorize.getClient_id(), oidcAuthorize.getRedirect_uri())) {
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

            if (!oneIdService.verifyRedirectUri(oidcAuth.getClient_id(), oidcAuth.getRedirect_uri())) {
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

            token = oneIdService.rsaDecryptToken(token);
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
            return Result.resultOidc(HttpStatus.OK, MessageCodeConfig.S0001, res);
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
            String decryptedToken = oneIdService.rsaDecryptToken(accessToken);
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
                String profileTemp = oneIdService.oidcScopeAuthingMapping().getOrDefault(profile, profile);
                Object value = oneIdService.jsonObjObjectValue(userObj, profileTemp);
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
                    String profileTemp = oneIdService.oidcScopeAuthingMapping().getOrDefault(claim, claim);
                    Object value = oneIdService.jsonObjObjectValue(userObj, profileTemp);
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

    private HashMap<String, String[]> oidcScopeOthers() {
        HashMap<String, String[]> otherMap = new HashMap<>();
        for (String other : LoginConfig.OIDC_SCOPE_OTHER) {
            if (!StringUtils.hasText(other)) continue;
            String[] split = other.split("->");
            otherMap.put(split[0], split[1].split(","));
        }
        return otherMap;
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
        OneIdEntity.User user = oneIdUserDao.loginByPassword(account, oneIdService.getAccountType(account), password);

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
        String token = oneIdService.rsaDecryptToken(refreshToken);
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