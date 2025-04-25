package com.om.Service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Utils.HS256Util;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdThirdPartyDao;
import com.om.Dao.oneId.OneIdThirdPartyUserDao;
import com.om.Dao.oneId.OneIdUserDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.OneIdService;
import com.om.Service.inter.ThirdPartyServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.RSAUtil;
import com.om.config.LoginConfig;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Service
public class ThirdPartyServiceImpl implements ThirdPartyServiceInter {

    private static final Logger logger = LoggerFactory.getLogger(OidcServiceImplOneId.class);

    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    @Value("${rsa.authing.publicKey}")
    private String rsaAuthingPublicKey;

    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;

    @Autowired
    private OneIdThirdPartyDao oneIdThirdPartyDao;

    @Autowired
    private OneIdThirdPartyUserDao oneIdThirdPartyUserDao;

    @Autowired
    private RedisDao redisDao;

    @Autowired
    private OneIdUserDao oneIdUserDao;

    @Autowired
    OneIdService oneIdService;

    @Autowired
    OneIdAppDao oneIdAppDao;

    @Override
    public ResponseEntity<?> thirdPartyList(String clientId) {
        try {
            List<OneIdEntity.ThirdPartyClient> sources = oneIdThirdPartyDao.getAllClientsByAppId(clientId);

            if (sources == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066, null, null, null);
            }

            HashMap<String, String> sourceIds = new HashMap<>();
            for (OneIdEntity.ThirdPartyClient source : sources) {
                sourceIds.put(source.getName(), source.getId());
            }

            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, sourceIds, null);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyAuthorize(String clientId, String connId) {
        try {
            OneIdEntity.ThirdPartyClient source = oneIdThirdPartyDao.getClientByAssociation(clientId, connId);

            if (source == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066, null, null, null);
            }

            String thirdPartyLoginPage = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
                    source.getAuthorizeUrl(),
                    source.getClientId(),
                    String.format(LoginConfig.EXTERNAL_CALLBACK_URL, source.getId()),
                    source.getScopes(),
                    generateState());

            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).header(HttpHeaders.LOCATION, thirdPartyLoginPage).build();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyCallback(String connId, String code, String state, String appId) {
        try {
            // check state
            if (redisDao.get(state) == null) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null, null);
            }

            OneIdEntity.ThirdPartyClient source = oneIdThirdPartyDao.getClientById(connId);

            if (source == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066, null, null, null);
            }
            // app校验
            OneIdEntity.App app = oneIdAppDao.getAppInfo(appId);
            if (null == app) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00047, null, null, null);
            }
            String accessToken = null;
            if (Constant.GITCODE.equals(source.getName())) {
                accessToken = getAccessTokenByParam(source, code);
            } else {
                accessToken = getAccessTokenByBody(source, code);
            }
            if (StringUtils.isBlank(accessToken)) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
            }
            // token获取用户信息
            HttpResponse<JsonNode> responseUser = Unirest.get(source.getUserUrl())
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + accessToken)
                    .asJson();

            JSONObject user = null;
            if (responseUser.getStatus() == 200) {
                user = responseUser.getBody().getObject();
            } else {
                logger.error("thirdPartyCallback err: " + responseUser.getBody().toString());
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
            }
            // check if user exist
            String userIdInPd = user.get("id").toString();
            OneIdEntity.User userInDb = oneIdThirdPartyDao.getUserByIdInProvider(userIdInPd, source.getName());
            if (userInDb == null) {
                // store userinfo
                int expire = LoginConfig.AUTHING_TOKEN_EXPIRE_SECONDS;
                user.put("code", 200);
                redisDao.set(source.getName() + userIdInPd + state, user.toString(), (long) expire);

                // create jwt token
                LocalDateTime nowDate = LocalDateTime.now();
                Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());

                LocalDateTime expireDate = nowDate.plusSeconds(expire);
                Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());
                String token = JWT.create()
                        .withAudience(userIdInPd) //谁接受签名
                        .withIssuedAt(issuedAt) //生成签名的时间
                        .withExpiresAt(expireAt) //过期时间
                        .withJWTId(CodeUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                        .withClaim("provider", source.getName())
                        .withClaim("userIdInPd", userIdInPd)
                        .withClaim("appId", appId)
                        .sign(Algorithm.HMAC256(userIdInPd + authingTokenBasePassword));

                RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
                token = RSAUtil.publicEncrypt(token, publicKey);

                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00034, null, token, null);
            } else {
                String idToken = HS256Util.getHS256Token(userInDb, appId, app.getAppSecret());
                if (idToken == null) {
                    return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
                }
                return oneIdService.loginSuccessSetToken(userInDb, idToken, appId);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
        }
    }

    private String getAccessTokenByParam(OneIdEntity.ThirdPartyClient source, String code) {
        String accessToken = "";
        StringBuilder tokenUrl = new StringBuilder(source.getTokenUrl());
        tokenUrl.append("?grant_type=authorization_code&code=").append(code).append("&client_id=")
                .append(source.getClientId()).append("&client_secret=").append(source.getClientSecret());
        HttpResponse<JsonNode> response = Unirest.post(tokenUrl.toString())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .asJson();
        if (response.getStatus() == 200) {
            accessToken = response.getBody().getObject().getString("access_token");
        } else {
            logger.error("thirdPartyCallback err: " + response.getBody().toString());
        }
        return accessToken;
    }

    private String getAccessTokenByBody(OneIdEntity.ThirdPartyClient source, String code) {
        // code换token
        String accessToken = "";
        String body = String.format("{\"client_id\": \"%s\", \"client_secret\": \"%s\", " +
                        "\"code\": \"%s\", \"redirect_uri\": \"%s\", \"grant_type\": \"authorization_code\"}",
                source.getClientId(), source.getClientSecret(), code,
                String.format(LoginConfig.EXTERNAL_CALLBACK_URL, source.getId()));
        HttpResponse<JsonNode> response = Unirest.post(source.getTokenUrl())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .body(body)
                .asJson();
        if (response.getStatus() == 200) {
            accessToken = response.getBody().getObject().getString("access_token");
        } else {
            logger.error("thirdPartyCallback err: " + response.getBody().toString());
        }
        return accessToken;
    }

    @Override
    public ResponseEntity<?> thirdPartyCreateUser(String token, String state) {
        try {
            token = RSAUtil.privateDecrypt(token, RSAUtil.getPrivateKey(rsaAuthingPrivateKey));

            DecodedJWT decode = JWT.decode(token);

            String provider = decode.getClaims().get("provider").asString();
            String userIdInPd = decode.getClaims().get("userIdInPd").asString();
            String appId = decode.getClaims().get("appId").asString();

            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(userIdInPd + authingTokenBasePassword)).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);

            String redisKey = provider + userIdInPd + state;
            String thirdPartyUserJson = (String) redisDao.get(redisKey);

            JSONObject thirdPartyUserObject = new JSONObject(thirdPartyUserJson);

            OneIdEntity.ThirdPartyUser thirdPartyUser = toThirdPartyUser(provider, thirdPartyUserObject);
            if (thirdPartyUser == null) {
                throw new Exception("no support provider");
            }

            if (oneIdThirdPartyUserDao.getThirdPartyUserByProvider(provider, userIdInPd) != null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00067, null, null, null);
            }
            OneIdEntity.App app = oneIdAppDao.getAppInfo(appId);
            OneIdEntity.User user = new OneIdEntity.User();
            user.setIdentities(new ArrayList<>(Collections.singletonList(thirdPartyUser)));
            user.setUsername(provider + "_" + thirdPartyUser.getUsername());
            OneIdEntity.User u = oneIdThirdPartyUserDao.createCompositeUser(user);
            if (u == null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00068, null, null, null);
            }

            redisDao.remove(redisKey);

            user.setId(u.getId());
            String idToken = HS256Util.getHS256Token(user, appId, app.getAppSecret());
            if (idToken == null) {
                return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
            }
            return oneIdService.loginSuccessSetToken(user, idToken, appId);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null, null);
        }

    }

    @Override
    public ResponseEntity<?> thirdPartyBindUser(String bindToken, String userToken, String state) {
        try {
            // get third party user
            String token = RSAUtil.privateDecrypt(bindToken, RSAUtil.getPrivateKey(rsaAuthingPrivateKey));
            DecodedJWT decode = JWT.decode(token);

            String provider = decode.getClaims().get("provider").asString();
            String userIdInPd = decode.getClaims().get("userIdInPd").asString();
            String appId = decode.getClaims().get("appId").asString();
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(userIdInPd + authingTokenBasePassword)).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            String redisKey = provider + userIdInPd + state;
            String thirdPartyUserJson = (String) redisDao.get(redisKey);

            JSONObject thirdPartyUserObject = new JSONObject(thirdPartyUserJson);
            OneIdEntity.ThirdPartyUser thirdPartyUser = toThirdPartyUser(provider, thirdPartyUserObject);
            if (thirdPartyUser == null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null, null);
            }

            if (oneIdThirdPartyUserDao.getThirdPartyUserByProvider(provider, userIdInPd) != null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00067, null, null, null);
            }

            // get user id
            decode = JWT.decode(userToken);
            if (CollectionUtils.isEmpty(decode.getAudience())) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00071, null, null, null);
            }
            String username = decode.getAudience().get(0);

            OneIdEntity.User user = oneIdUserDao.getUserInfo(username, "username");
            if (user == null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00034, null, null, null);
            }

            user = oneIdThirdPartyUserDao.createThirdPartyUser(thirdPartyUser, user.getId());
            if (user == null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00068, null, null, null);
            }

            redisDao.remove(redisKey);
            OneIdEntity.App app = oneIdAppDao.getAppInfo(appId);
            String idToken = HS256Util.getHS256Token(user, appId, app.getAppSecret());
            if (idToken == null) {
                return Result.resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.OIDC_E00005, null);
            }
            return oneIdService.loginSuccessSetToken(user, idToken, appId);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyUnbindUser(String token, String provider) {
        try {
            DecodedJWT decode = JWT.decode(token);
            String username = decode.getAudience().get(0);
            OneIdEntity.User user = oneIdUserDao.getUserInfo(username, "username");
            if (user == null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00034, null, null, null);
            }

            boolean isSuccess = oneIdThirdPartyUserDao.deleteThirdPartyUser(user.getId(), provider);
            if (isSuccess) {
                return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, null, null);
            }
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00069, null, null, null);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null, null);
        }
    }

    public OneIdEntity.ThirdPartyUser toThirdPartyUser(String provider, JSONObject thirdPartyUserObject) {
        OneIdEntity.ThirdPartyUser thirdPartyUser = new OneIdEntity.ThirdPartyUser();
        thirdPartyUser.setProvider(provider);
        switch (provider) {
            case "github":
                if (! thirdPartyUserObject.isNull("login")) {
                    thirdPartyUser.setUsername(thirdPartyUserObject.getString("login"));
                }
                if (! thirdPartyUserObject.isNull("email")) {
                    thirdPartyUser.setEmail(thirdPartyUserObject.getString("email"));
                }
                if (! thirdPartyUserObject.isNull("name")) {
                    thirdPartyUser.setName(thirdPartyUserObject.getString("name"));
                }
                if (! thirdPartyUserObject.isNull("id")) {
                    thirdPartyUser.setUserIdInIdp(Integer.toString(thirdPartyUserObject.getInt("id")));
                }

                break;
            case "gitee":
                if (! thirdPartyUserObject.isNull("login")) {
                    thirdPartyUser.setUsername(thirdPartyUserObject.getString("login"));
                }
                if (! thirdPartyUserObject.isNull("email")) {
                    thirdPartyUser.setEmail(thirdPartyUserObject.getString("email"));
                }
                if (! thirdPartyUserObject.isNull("name")) {
                    thirdPartyUser.setName(thirdPartyUserObject.getString("name"));
                }
                if (! thirdPartyUserObject.isNull("id")) {
                    thirdPartyUser.setUserIdInIdp(Integer.toString(thirdPartyUserObject.getInt("id")));
                }
                break;
            case Constant.GITCODE:
                if (! thirdPartyUserObject.isNull("login")) {
                    thirdPartyUser.setUsername(thirdPartyUserObject.getString("login"));
                }
                if (! thirdPartyUserObject.isNull("email")) {
                    thirdPartyUser.setEmail(thirdPartyUserObject.getString("email"));
                }
                if (! thirdPartyUserObject.isNull("name")) {
                    thirdPartyUser.setName(thirdPartyUserObject.getString("name"));
                }
                if (! thirdPartyUserObject.isNull("id")) {
                    thirdPartyUser.setUserIdInIdp(thirdPartyUserObject.getString("id"));
                }
                break;
            default:
                thirdPartyUser = null;
        }
        return thirdPartyUser;
    }

    private String generateState() {
        String state = UUID.randomUUID().toString().replaceAll("-", "");
        long expireSeconds = Long.parseLong("300");
        redisDao.set(state, "valid", expireSeconds);

        return state;
    }

}
