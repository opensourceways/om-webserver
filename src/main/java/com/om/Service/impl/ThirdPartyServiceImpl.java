package com.om.Service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdThirdPartyDao;
import com.om.Dao.oneId.OneIdThirdPartyUserDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.JwtTokenCreateService;
import com.om.Service.inter.ThirdPartyServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import com.om.config.LoginConfig;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    private Environment env;

    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    @Autowired
    private OneIdThirdPartyDao oneIdThirdPartyDao;

    @Autowired
    private OneIdThirdPartyUserDao oneIdThirdPartyUserDao;

    @Autowired
    private RedisDao redisDao;

    @Autowired
    private HttpServletRequest servletRequest;

    @Autowired
    private HttpServletResponse servletResponse;

    private static HashMap<String, Boolean> domain2secure;



    @PostConstruct
    public void init() {
        domain2secure = HttpClientUtils.getConfigCookieInfo(Objects.requireNonNull(env.getProperty("cookie.token.domains")), Objects.requireNonNull(env.getProperty("cookie.token.secures")));
    }

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
                    String.format(env.getProperty("external.callback.url"), source.getId()),
                    source.getScopes(),
                    generateState());

            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).header(HttpHeaders.LOCATION, thirdPartyLoginPage).build();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyCallback(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                                String connId, String code, String state, String appId) {
        try {
            // check state
            if (redisDao.get(state) == null) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null, null);
            }

            OneIdEntity.ThirdPartyClient source = oneIdThirdPartyDao.getClientById(connId);

            if (source == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066, null, null, null);
            }

            // code换token
            String body = String.format("{\"client_id\": \"%s\", \"client_secret\": \"%s\", " +
                            "\"code\": \"%s\", \"redirect_uri\": \"%s\", \"grant_type\": \"authorization_code\"}",
                    source.getClientId(), source.getClientSecret(), code,
                    String.format(env.getProperty("external.callback.url"), source.getId()));
            HttpResponse<JsonNode> response = Unirest.post(source.getTokenUrl())
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            String accessToken = null;
            if (response.getStatus() == 200) {
                accessToken = response.getBody().getObject().getString("access_token");
            } else {
                logger.error("thirdPartyCallback err: " + response.getBody().toString());
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
                Long expire = Long.parseLong(env.getProperty("authing.token.expire.seconds", Constant.DEFAULT_EXPIRE_SECOND));
                user.put("code", 200);
                redisDao.set(source.getName() + userIdInPd, user.toString(), expire);

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
                        .withClaim("userinfo", userIdInPd)
                        .sign(Algorithm.HMAC256(userIdInPd + authingTokenBasePassword));

                RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
                token = RSAUtil.publicEncrypt(token, publicKey);

                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00034, null, token, null);
            } else {
                return login(servletRequest, servletResponse, userInDb, appId);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyCreateUser(String token) {
        try {
            token = RSAUtil.privateDecrypt(token, RSAUtil.getPrivateKey(rsaAuthingPrivateKey));

            DecodedJWT decode = JWT.decode(token);

            String provider = decode.getClaims().get("provider").asString();
            String userIdInPd = decode.getClaims().get("userinfo").asString();

            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(userIdInPd + authingTokenBasePassword)).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);

            String redisKey = provider + userIdInPd;
            String thirdPartyUserJson = (String) redisDao.get(redisKey);
            JSONObject thirdPartyUserObject = new JSONObject(thirdPartyUserJson);

            OneIdEntity.ThirdPartyUser thirdPartyUser = toThirdPartyUser(provider, thirdPartyUserObject);
            if (thirdPartyUser == null) {
                throw new Exception("no support provider");
            }

            if (oneIdThirdPartyUserDao.getThirdPartyUserByProvider(provider, userIdInPd) != null) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00067, null, null, null);
            }

            OneIdEntity.User user = new OneIdEntity.User();
            user.setIdentities(new ArrayList<>(Collections.singletonList(thirdPartyUser)));
            user.setUsername(thirdPartyUser.getUsername());
            int r = oneIdThirdPartyUserDao.createCompositeUser(user);
            if (r <= 0) {
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00068, null, null, null);
            }

            String idToken = user.getId();

            return login(servletRequest, servletResponse, user, idToken);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00048, null, null, null);
        }

    }


    public OneIdEntity.ThirdPartyUser toThirdPartyUser(String provider, JSONObject thirdPartyUserObject) {
        OneIdEntity.ThirdPartyUser thirdPartyUser = new OneIdEntity.ThirdPartyUser();
        switch (provider) {
            case "github":
                thirdPartyUser.setProvider(provider);
                thirdPartyUser.setUsername(provider + "_" + thirdPartyUserObject.getString("login"));
                thirdPartyUser.setEmail(thirdPartyUserObject.getString("email"));
                thirdPartyUser.setNickname(thirdPartyUserObject.getString("login"));
                thirdPartyUser.setName(thirdPartyUserObject.getString("name"));
                thirdPartyUser.setUserIdInIdp("id");
                break;
            case "gitee":
                thirdPartyUser.setProvider(provider);
                thirdPartyUser.setUsername(provider + "_" + thirdPartyUserObject.getString("login"));
                thirdPartyUser.setEmail(thirdPartyUserObject.getString("email"));
                thirdPartyUser.setNickname(thirdPartyUserObject.getString("login"));
                thirdPartyUser.setName(thirdPartyUserObject.getString("name"));
                thirdPartyUser.setUserIdInIdp("id");
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

    private ResponseEntity<?> login(HttpServletRequest servletRequest, HttpServletResponse servletResponse, OneIdEntity.User user, String appId) {
        Map<String, String> tokens = jwtTokenCreateService.authingUserToken(appId, user.getId(), user.getUsername(), "", "", user.getId());
        String token = tokens.get(Constant.TOKEN_Y_G_);
        String verifyToken = tokens.get(Constant.TOKEN_U_T_);

        // 写cookie
        String cookieTokenName = LoginConfig.COOKIE_TOKEN_NAME;
        String verifyTokenName = LoginConfig.COOKIE_VERIFY_TOKEN_NAME;

        int expire = LoginConfig.AUTHING_TOKEN_EXPIRE_SECONDS;
        int maxAge = LoginConfig.AUTHING_COOKIE_MAX_AGE;
        HttpClientUtils.setCookie(servletRequest, servletResponse, cookieTokenName,
                token, true, maxAge, "/", domain2secure);
        HttpClientUtils.setCookie(servletRequest, servletResponse, verifyTokenName,
                verifyToken, false, expire, "/", domain2secure);

        HashMap<String, String> userInfo = new HashMap<>();
        userInfo.put("username", user.getUsername());
        userInfo.put("email", user.getEmail());
        userInfo.put("phone", user.getPhone());
        userInfo.put("token", verifyToken);

        return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userInfo, null);
    }
}
