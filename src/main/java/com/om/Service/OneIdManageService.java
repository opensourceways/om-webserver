/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.Service;

import cn.authing.core.types.Application;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.util.HashMap;
import java.util.Map;

@Service
public class OneIdManageService {
    @Autowired
    Environment env;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    ObjectMapper objectMapper;

    private static final Logger logger =  LoggerFactory.getLogger(OneIdManageService.class);

    static final String[] PARAMETER_DEFAULT_VALUE = new String[]{""};

    static final String MSG_DEFAULT = "Internal Server Error";

    static final String TOKEN_REGEX = "token_info:";

    public ResponseEntity tokenApply(Map<String, String> body) {
        try {
            String grantType = body.get("grant_type");
            if (StringUtils.isBlank(grantType)) {
                return result(HttpStatus.BAD_REQUEST,
                        "grant_type must be not blank", null);
            }

            /*
             * grantType=token,生成token和refresh_token
             * grantType=refresh_token,生成新的token和refresh_token
             */
            if (grantType.equalsIgnoreCase("token")) {
                String appId = body.get("app_id");
                String appSecret = body.get("app_secret");
                return tokenApply(appId, appSecret);
            } else if (grantType.equalsIgnoreCase("refresh_token")) {
                String token = body.get("token");
                String refreshToken = body.get("refresh_token");
                return refreshToken(token, refreshToken);
            } else {
                return result(HttpStatus.BAD_REQUEST,
                        "grant_type must be token or refresh_token", null);
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MSG_DEFAULT, null);
        }

    }

    /**
     * APP是否存在，且密码是否正确
     *
     * @param appId     appId
     * @param appSecret appSecret
     * @return app是否正确
     */
    private boolean isAppCorrect(String appId, String appSecret) {
        Application app = authingUserDao.getAppById(appId);
        return app != null && appSecret.equals(app.getSecret());
    }

    /**
     * 生成token和refresh_token
     *
     * @param appId     appId
     * @param appSecret appSecret
     * @return token和refresh_token
     * @throws JsonProcessingException 创建失败
     */
    private Map<String, Object> createTokens(String appId, String appSecret)
            throws JsonProcessingException {
        // 过期时间
        long tokenExpire = Long.parseLong(
                env.getProperty("app.manager.token.expire", "1800"));
        long refTokenExpire = Long.parseLong(
                env.getProperty("app.manager.refresh.token.expire", "28800"));

        // jwt格式token和refresh_token
        String tokenJwt = jwtTokenCreateService.getAppManagerToken(
                appId, appSecret, tokenExpire);
        String refTokenJwt = jwtTokenCreateService.getAppManagerToken(
                appId, appSecret, refTokenExpire);

        // token和refresh_token的hash
        String token = DigestUtils.md5DigestAsHex(tokenJwt.getBytes());
        String refreshToken = DigestUtils.md5DigestAsHex(refTokenJwt.getBytes());

        // jwt格式token和refresh_token保存在服务端
        HashMap<String, Object> jwtTokenMap = new HashMap<>();
        jwtTokenMap.put("token", tokenJwt);
        jwtTokenMap.put("refresh_token", refTokenJwt);
        jwtTokenMap.put("app_id", appId);
        jwtTokenMap.put("app_secret", appSecret);
        String tokenStr = objectMapper.writeValueAsString(jwtTokenMap);
        redisDao.set(token, TOKEN_REGEX + tokenStr, refTokenExpire);

        // 返回token和refresh_token的hash
        HashMap<String, Object> tokenMap = new HashMap<>();
        tokenMap.put("token", token);
        tokenMap.put("refresh_token", refreshToken);
        return tokenMap;
    }

    /**
     * 申请app管理员的token和refresh_token
     *
     * @param appId     appId
     * @param appSecret appSecret
     * @return token和refresh_token
     */
    private ResponseEntity tokenApply(String appId, String appSecret) {
        try {
            if (!isAppCorrect(appId, appSecret)) {
                return result(HttpStatus.BAD_REQUEST,
                        "app id or secret error", null);
            }

            Map<String, Object> tokens = createTokens(appId, appSecret);
            return result(HttpStatus.OK, "OK", tokens);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MSG_DEFAULT, null);
        }
    }

    /**
     * 使用旧token和refresh_token生成新的token和refresh_token
     *
     * @param oldToken    旧token
     * @param oldRefToken 旧refresh_token
     * @return 新的token和refresh_token
     */
    private ResponseEntity refreshToken(String oldToken, String oldRefToken) {
        try {
            // 校验旧的token和refresh_token
            Object checkRes = checkTokens(oldToken, oldRefToken);
            if (!(checkRes instanceof JsonNode)) {
                return result(HttpStatus.BAD_REQUEST, (String) checkRes, null);
            }
            JsonNode tokenInfo = (JsonNode) checkRes;

            // 生成新的token和refresh_token，失效旧的
            String appId = tokenInfo.get("app_id").asText();
            String appSecret = tokenInfo.get("app_secret").asText();
            Map<String, Object> newTokens = createTokens(appId, appSecret);
            redisDao.remove(oldToken);

            return result(HttpStatus.OK, "OK", newTokens);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MSG_DEFAULT, null);
        }
    }

    /**
     * 校验token和refresh_token
     *
     * @param token        token
     * @param refreshToken refresh_token
     * @return 校验正确返回服务端存储的token信息
     */
    private Object checkTokens(String token, String refreshToken) {
        try {
            if (StringUtils.isBlank(token) || StringUtils.isBlank(refreshToken)) {
                return "must contain token and refresh_token";
            }

            // 校验token
            String tokenStr = (String) redisDao.get(token);
            if (StringUtils.isBlank(tokenStr)) {
                return "token error or expire";
            }

            // 校验refresh_token是否同缓存中一致
            String tokenInfo = tokenStr.replace(TOKEN_REGEX, "");
            JsonNode jsonNode = objectMapper.readTree(tokenInfo);
            String refTokenJwt = jsonNode.get("refresh_token").asText();
            if (!refreshToken.equals(DigestUtils.md5DigestAsHex(refTokenJwt.getBytes()))) {
                return "token error or expire";
            }

            // 校验refresh_token是否正确或过期
            String appSecret = jsonNode.get("app_secret").asText();
            String password = appSecret + env.getProperty("authing.token.base.password");
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(password)).build();
            jwtVerifier.verify(refTokenJwt);

            return jsonNode;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return "token error or expire";
        }
    }

    private String getPara(Map<String, String[]> parameterMap, String paraName) {
        return parameterMap.getOrDefault(paraName, PARAMETER_DEFAULT_VALUE)[0];
    }

    private ResponseEntity result(HttpStatus status, String msg, Map<String, Object> claim) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("status", status.value());
        res.put("msg", msg);
        if (claim != null) {
            res.putAll(claim);
        }
        return new ResponseEntity<>(res, status);
    }
}
