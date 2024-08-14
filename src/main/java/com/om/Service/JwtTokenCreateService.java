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
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Utils.CodeUtil;
import com.om.Utils.EncryptionService;
import com.om.Utils.RSAUtil;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import jakarta.servlet.http.HttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class JwtTokenCreateService {
    /**
     * 注入 RedisDao 依赖.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 注入加密类.
     */
    @Autowired
    private EncryptionService encryptionService;

    /**
     * 注入 CodeUtil 依赖.
     */
    @Autowired
    private CodeUtil codeUtil;

    /**
     * 过期时间（秒）：Authing Token.
     */
    @Value("${authing.token.expire.seconds}")
    private String authingTokenExpireSeconds;

    /**
     * 基础密码：Authing Token.
     */
    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    /**
     * 基础密码：OIDC Token.
     */
    @Value("${oidc.token.base.password}")
    private String oidcTokenBasePassword;

    /**
     * RSA公钥：Authing.
     */
    @Value("${rsa.authing.publicKey}")
    private String rsaAuthingPublicKey;

    /**
     * 基础密码：Token.
     */
    @Value("${token.base.password}")
    private String tokenBasePassword;

    /**
     * 过期时间（秒）：Token.
     */
    @Value("${token.expire.seconds}")
    private String tokenExpireSeconds;

    /**
     * OneID隐私版本.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;


    /**
     * 静态日志记录器，用于记录 JwtTokenCreateService 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenCreateService.class);

    /**
     * 为 Authing 用户生成令牌.
     *
     * @param appId                     应用ID
     * @param userId                    用户ID
     * @param username                  用户名
     * @param permission                权限
     * @param inputPermission           输入的权限
     * @param idToken                   ID令牌
     * @param oneidPrivacyVersionAccept OneID隐私版本接受标志
     * @return 包含生成的令牌的字符串数组
     */
    @SneakyThrows
    public String[] authingUserToken(String appId, String userId, String username,
                                     String permission, String inputPermission,
                                     String idToken, String oneidPrivacyVersionAccept) {
        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        long expireSeconds = 60;
        try {
            expireSeconds = Integer.parseInt(authingTokenExpireSeconds);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());
        Date headTokenExpireAt = Date.from(expireDate.atZone(ZoneId.systemDefault())
                .toInstant().plusSeconds(expireSeconds));

        String headToken = JWT.create()
                .withAudience(username) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(headTokenExpireAt) //过期时间
                .withJWTId(codeUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                .sign(Algorithm.HMAC256(authingTokenBasePassword));
        String verifyToken = DigestUtils.md5DigestAsHex(headToken.getBytes(StandardCharsets.UTF_8));
        idToken = encryptionService.publicEncrypt(idToken);
        redisDao.set("idToken_" + verifyToken, idToken, expireSeconds);
        String permissionStr = Base64.getEncoder().encodeToString(permission.getBytes(StandardCharsets.UTF_8));

        String token = JWT.create()
                .withAudience(userId) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .withJWTId(codeUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                .withClaim("permission", permissionStr)
                .withClaim("inputPermission", inputPermission)
                .withClaim("verifyToken", verifyToken)
                .withClaim("client_id", appId)
                .withClaim("oneidPrivacyAccepted", oneidPrivacyVersionAccept)
                .sign(Algorithm.HMAC256(permission + authingTokenBasePassword));
        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            return new String[]{RSAUtil.publicEncrypt(token, publicKey), headToken};
        } catch (Exception e) {
            System.out.println("RSA Encrypt error");
            return new String[]{token, headToken};
        }
    }

    /**
     * 刷新 Authing 用户令牌.
     *
     * @param request  HTTP请求对象
     * @param idToken idToken
     * @param userId   用户ID
     * @param claimMap 包含声明的映射
     * @return 包含生成的令牌的字符串数组
     */
    public String[] refreshAuthingUserToken(HttpServletRequest request, String idToken,
                                            String userId, Map<String, Claim> claimMap) {
        String headerJwtToken = request.getHeader("token");
        String appId = claimMap.get("client_id").asString();
        String inputPermission = claimMap.get("inputPermission").asString();
        String permission = new String(Base64.getDecoder()
                .decode(claimMap.get("permission").asString()
                        .getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

        // 生成新的token和headToken
        List<String> audience = JWT.decode(headerJwtToken).getAudience();
        String username = ((audience == null) || audience.isEmpty()) ? "" : audience.get(0);
        return authingUserToken(appId, userId, username, permission, inputPermission, idToken, oneidPrivacyVersion);
    }

    /**
     * 生成 OIDC 令牌.
     *
     * @param userId        用户ID
     * @param issuer        颁发者
     * @param scope         范围
     * @param expireSeconds 过期时间（秒）
     * @param expireAt      过期时间点
     * @return OIDC 令牌字符串
     */
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

    /**
     * 获取应用管理员令牌.
     *
     * @param appId       应用ID
     * @param appSecret   应用密钥
     * @param tokenExpire 令牌过期时间
     * @return 应用管理员令牌字符串
     */
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

    /**
     * 生成重置密码令牌.
     *
     * @param account       账号信息
     * @param expireSeconds 过期时间（秒）
     * @return 重置密码令牌字符串
     */
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
