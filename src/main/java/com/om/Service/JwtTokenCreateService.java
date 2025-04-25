/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Service;

import cn.authing.core.types.User;
import com.anji.captcha.util.StringUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdUserDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Utils.CodeUtil;
import com.om.Utils.RSAUtil;
import com.om.Vo.TokenUser;
import com.om.config.LoginConfig;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Service
public class JwtTokenCreateService {
    @Autowired
    RedisDao redisDao;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    private Environment env;

    @Autowired
    private OneIdUserDao oneIdUserDao;

    @Value("${authing.token.expire.seconds}")
    private String authingTokenExpireSeconds;

    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    @Value("${oidc.token.base.password}")
    private String oidcTokenBasePassword;

    @Value("${rsa.authing.publicKey}")
    private String rsaAuthingPublicKey;

    @Value("${token.base.password}")
    private String tokenBasePassword;

    @Value("${token.expire.seconds}")
    private String tokenExpireSeconds;

    /**
     * OneID隐私版本.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

    private static final Logger logger =  LoggerFactory.getLogger(JwtTokenCreateService.class);

    public String getToken(TokenUser user) {
        if (!user.getCommunity().equalsIgnoreCase("openeuler")
                && !user.getCommunity().equalsIgnoreCase("opengauss")
                && !user.getCommunity().equalsIgnoreCase("mindspore")
                && !user.getCommunity().equalsIgnoreCase("openlookeng")) {
            return null;
        }

        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        int expireSeconds = Integer.parseInt(tokenExpireSeconds);
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        String basePassword = tokenBasePassword;

        return JWT.create()
                .withAudience(user.getUsername()) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .sign(Algorithm.HMAC256(user.getPassword() + basePassword));
    }

    @SneakyThrows
    public Map<String, String> authingUserToken(String appId, String userId, String username, String permission,
            String inputPermission, String idToken, String oneidPrivacyVersionAccept) {
        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        int expireSeconds = LoginConfig.AUTHING_TOKEN_EXPIRE_SECONDS;

        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());
        Date headTokenExpireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant().plusSeconds(expireSeconds));
        if (StringUtils.isBlank(username)) {
            OneIdEntity.User user = oneIdUserDao.getUserInfo(userId, "id");
            if (user != null && StringUtils.isNotBlank(user.getUsername())) {
                username = user.getUsername();
            }
        }
        String headToken = JWT.create()
                .withAudience(username) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(headTokenExpireAt) //过期时间
                .withJWTId(CodeUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                .sign(Algorithm.HMAC256(authingTokenBasePassword));
        String verifyToken = DigestUtils.md5DigestAsHex(headToken.getBytes());

        redisDao.set(Constant.ID_TOKEN_PREFIX + verifyToken, idToken, (long)expireSeconds);

        StringBuilder perStr = new StringBuilder();
        ArrayList<String> pers = authingUserDao.getUserPermission(userId, env.getProperty("openeuler.groupCode"));
        for (String per : pers) {
            perStr.append(per).append(",");
        }
        perStr = new StringBuilder(Base64.getEncoder().encodeToString(perStr.toString().getBytes()));
        String permissionStr = Base64.getEncoder().encodeToString(permission.getBytes());

        String token = JWT.create()
                .withAudience(userId) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .withJWTId(CodeUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                .withClaim("permission", permissionStr)
                .withClaim("inputPermission", inputPermission)
                .withClaim("verifyToken", verifyToken)
                .withClaim("permissionList", perStr.toString())
                .withClaim("client_id", appId)
                .withClaim("oneidPrivacyAccepted", oneidPrivacyVersionAccept)
                .sign(Algorithm.HMAC256(permission + authingTokenBasePassword));

        HashMap<String, String> result = new HashMap<>();
        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            result.put(Constant.TOKEN_Y_G_, RSAUtil.publicEncrypt(token, publicKey));
            result.put(Constant.TOKEN_U_T_, headToken);
        } catch (Exception e) {
            logger.error("RSA Encrypt error: " + e.getMessage());
            result.put(Constant.TOKEN_Y_G_, token);
            result.put(Constant.TOKEN_U_T_, headToken);
        }
        return result;
    }

    public Map<String, String> refreshAuthingUserToken(HttpServletRequest request, HttpServletResponse response,
                                                       String userId, Map<String, Claim> claimMap) {
        String headerJwtToken = request.getHeader("token");
        String headJwtTokenMd5 = DigestUtils.md5DigestAsHex(headerJwtToken.getBytes());
        String appId = claimMap.get("client_id").asString();
        String inputPermission = claimMap.get("inputPermission").asString();
        String idToken = (String) redisDao.get(Constant.ID_TOKEN_PREFIX + headJwtTokenMd5);
        String permission = new String(Base64.getDecoder().decode(claimMap.get("permission").asString().getBytes()));
        String oneidPrivacyVersionAccept = "";
        if (claimMap.containsKey("oneidPrivacyAccepted")) {
            oneidPrivacyVersionAccept = claimMap.get("oneidPrivacyAccepted").asString();
            if (!oneidPrivacyVersion.equals(oneidPrivacyVersionAccept)) {
                String privacyVersionNew = (String) redisDao.get(Constant.REDIS_KEY_PRIVACY_CHANGE + userId);
                if (privacyVersionNew != null) {
                    oneidPrivacyVersionAccept = privacyVersionNew;
                }
            }
        }
        // 生成新的token和headToken
        List<String> audience = JWT.decode(headerJwtToken).getAudience();
        String username = ((audience == null) || audience.isEmpty()) ? "" : audience.get(0);
        return authingUserToken(appId, userId, username, permission, inputPermission, idToken, oneidPrivacyVersionAccept);
    }

    public String oidcToken(String userId, String issuer, String scope, long expireSeconds, Date expireAt) {
        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        expireAt = expireAt != null ? expireAt : Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        String token = JWT.create()
                .withIssuer(issuer) //签名
                .withAudience(userId) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .withClaim("scope", scope)
                .sign(Algorithm.HMAC256(userId + oidcTokenBasePassword));

        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            return RSAUtil.publicEncrypt(token, publicKey);
        } catch (Exception e) {
            System.out.println("RSA Encrypt error");
            return token;
        }
    }

    public String getAppManagerToken(String appId, String appSecret,
                                     long tokenExpire) {
        LocalDateTime nowDate = LocalDateTime.now();

        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());

        LocalDateTime expireDate = nowDate.plusSeconds(tokenExpire);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        return JWT.create()
                .withAudience(appId) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .sign(Algorithm.HMAC256(appSecret + authingTokenBasePassword));
    }

    public String resetPasswordToken(String account, long expireSeconds) {
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        String token = JWT.create()
                          .withAudience(account)
                          .withIssuedAt(issuedAt)
                          .withExpiresAt(expireAt)
                          .sign(Algorithm.HMAC256(account + tokenBasePassword));

        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            return RSAUtil.publicEncrypt(token, publicKey);
        } catch (Exception e) {
            System.out.println("RSA Encrypt error");
            return token;
        }
    }

}
