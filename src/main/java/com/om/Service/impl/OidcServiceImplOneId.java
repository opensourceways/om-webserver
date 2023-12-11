package com.om.Service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Result.Result;
import com.om.Service.JwtTokenCreateService;
import com.om.Service.inter.OidcServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.RSAUtil;
import com.om.Vo.dto.OidcAuth;
import com.om.Vo.dto.OidcAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@ConditionalOnProperty(value = "service.oidc", havingValue = "oidcServiceImplOneId")
public class OidcServiceImplOneId implements OidcServiceInter {

    private static final String OIDCISSUER = "ONEID";

    private static ObjectMapper objectMapper;

    @Autowired
    private Environment environment;

    @Autowired
    OneIdAppDao oneIdAppDao;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    @Autowired
    RedisDao redisDao;


    public final static List<String> RESPONSE_TYPE_AVAILABLE = Collections.singletonList("code");

    public final static List<String> SCOPE_AVAILABLE = Arrays.asList("openid", "profile", "email", "phone", "address", "offline_access");

    @Override
    public ResponseEntity<?> oidcAuthorize(OidcAuthorize oidcAuthorize) {
        try {
            if (!RESPONSE_TYPE_AVAILABLE.contains(oidcAuthorize.getResponse_type())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);
            }

            if (!verifyRedirectUri(oidcAuthorize.getClient_id(), oidcAuthorize.getRedirect_uri())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);
            }

            if (!StringUtils.hasText(oidcAuthorize.getScope())) {
                oidcAuthorize.setScope("openid profile");
            } else {
                List<String> scopeList = Arrays.asList(oidcAuthorize.getScope().split("\\s+"));
                if (!scopeList.contains("openid") || !scopeList.contains("profile")) {
                    return Result.resultOidc(HttpStatus.NOT_FOUND, "scope must contain <openid profile>", null);
                }
                for (String s : scopeList) {
                    if (!SCOPE_AVAILABLE.contains(s)) {
                        return Result.resultOidc(HttpStatus.NOT_FOUND, "  Unsupported scope", null);
                    }
                }
            }

            if (!StringUtils.hasText(oidcAuthorize.getState())) {
                oidcAuthorize.setState(UUID.randomUUID().toString().replaceAll("-", ""));
            }

            // 重定向到登录页
            String loginPage = environment.getProperty("oidc.login.page");
            if ("register".equals(oidcAuthorize.getEntity())) {
                loginPage = environment.getProperty("oidc.register.page");
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
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    @Override
    public ResponseEntity<?> oidcAuth(String token, OidcAuth oidcAuth) {
        try {
            if (!RESPONSE_TYPE_AVAILABLE.contains(oidcAuth.getResponse_type())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);
            }

            if (!verifyRedirectUri(oidcAuth.getClient_id(), oidcAuth.getRedirect_uri())) {
                return Result.resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);
            }

            if (!StringUtils.hasText(oidcAuth.getScope())) {
                oidcAuth.setScope("openid profile");
            } else {
                List<String> scopeList = Arrays.asList(oidcAuth.getScope().split("\\s+"));
                if (!scopeList.contains("openid") || !scopeList.contains("profile")) {
                    return Result.resultOidc(HttpStatus.NOT_FOUND, "scope must contain <openid profile>", null);
                }
                for (String s : scopeList) {
                    if (!SCOPE_AVAILABLE.contains(s)) {
                        return Result.resultOidc(HttpStatus.NOT_FOUND, "  Unsupported scope", null);
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

            long codeExpire = Long.parseLong(environment.getProperty("oidc.code.expire", "60"));
            long accessTokenExpire = Long.parseLong(environment.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(environment.getProperty("oidc.refresh.token.expire", "86400"));

            String accessToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, oidcAuth.getScope(), accessTokenExpire, null);
            String refreshToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, oidcAuth.getScope(), refreshTokenExpire, null);

            String code = CodeUtil.randomStrBuilder(32);

            HashMap<String, String> codeMap = new HashMap<>();
            codeMap.put("accessToken", accessToken);
            codeMap.put("refreshToken", refreshToken);
            codeMap.put("idToken", idToken);
            codeMap.put("appId", oidcAuth.getClient_id());
            codeMap.put("redirectUri", oidcAuth.getRedirect_uri());
            codeMap.put("scope", oidcAuth.getScope());
            String codeMapStr = "oidcCode:" + objectMapper.writeValueAsString(codeMap);
            redisDao.set(code, codeMapStr, codeExpire);

            HashMap<String, String> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessToken);
            userTokenMap.put("refresh_token", refreshToken);
            userTokenMap.put("idToken", idToken);
            userTokenMap.put("scope", oidcAuth.getScope());
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes()), userTokenMapStr, refreshTokenExpire);

            String res = String.format("%s?code=%s&state=%s", oidcAuth.getRedirect_uri(), code, oidcAuth.getState());
            return Result.resultOidc(HttpStatus.OK, "OK", res);
        } catch (Exception e) {
            return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    public boolean verifyRedirectUri(String clientId, String redirectUri) throws Exception {
        OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
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

    private String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(environment.getProperty("rsa.authing.privateKey"));
        return RSAUtil.privateDecrypt(token, privateKey);
    }

}
