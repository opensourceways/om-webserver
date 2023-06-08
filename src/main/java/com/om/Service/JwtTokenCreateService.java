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

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Utils.RSAUtil;
import com.om.Vo.TokenUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Service
public class JwtTokenCreateService {
    @Autowired
    RedisDao redisDao;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    private Environment env;

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

    public String[] authingUserToken(String appId, String userId, String username,
                                     String permission, String inputPermission, String idToken) {
        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        long expireSeconds = 60;
        try {
            expireSeconds = Integer.parseInt(authingTokenExpireSeconds);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());
        Date headTokenExpireAt = Date.from(expireDate.atZone(ZoneId.systemDefault())
                .toInstant().plusSeconds(expireSeconds));

        String headToken = JWT.create()
                .withAudience(username) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(headTokenExpireAt) //过期时间
                .sign(Algorithm.HMAC256(authingTokenBasePassword));
        String verifyToken = DigestUtils.md5DigestAsHex(headToken.getBytes());
        redisDao.set("idToken_" + verifyToken, idToken, expireSeconds);

        String perStr = "";
        ArrayList<String> pers = authingUserDao.getUserPermission(userId, env.getProperty("openeuler.groupCode"));
        for (String per : pers) {
            perStr += per + ",";
        }
        perStr = Base64.getEncoder().encodeToString(perStr.getBytes());
        String permissionStr = Base64.getEncoder().encodeToString(permission.getBytes());

        String token = JWT.create()
                .withAudience(userId) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .withClaim("permission", permissionStr)
                .withClaim("inputPermission", inputPermission)
                .withClaim("verifyToken", verifyToken)
                .withClaim("permissionList", perStr)
                .withClaim("client_id", appId)
                .sign(Algorithm.HMAC256(permission + authingTokenBasePassword));
        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            return new String[]{RSAUtil.publicEncrypt(token, publicKey), headToken};
        } catch (Exception e) {
            System.out.println("RSA Encrypt error");
            return new String[]{token, headToken};
        }
    }

    public String[] refreshAuthingUserToken(HttpServletRequest request, HttpServletResponse response,
                                            String userId, Map<String, Claim> claimMap) {
        String headerJwtToken = request.getHeader("token");
        String headJwtTokenMd5 = DigestUtils.md5DigestAsHex(headerJwtToken.getBytes());
        String appId = claimMap.get("client_id").asString();
        String inputPermission = claimMap.get("inputPermission").asString();
        String idToken = (String) redisDao.get("idToken_" + headJwtTokenMd5);
        String permission = new String(Base64.getDecoder()
                .decode(claimMap.get("permission").asString().getBytes()));

        // 生成新的token和headToken
        String username = JWT.decode(headerJwtToken).getAudience().get(0);
        return authingUserToken(appId, userId, username, permission, inputPermission, idToken);
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
