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

package com.om.service;

import cn.authing.core.types.User;
import com.anji.captcha.util.StringUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.om.dao.AuthingManagerDao;
import com.om.dao.RedisDao;
import com.om.modules.MessageCodeConfig;
import com.om.result.Constant;
import com.om.service.bean.JwtCreatedParam;
import com.om.utils.CommonUtil;
import com.om.utils.LogUtil;
import com.om.utils.RSAUtil;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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
     * Authing的管理面接口.
     */
    @Autowired
    private AuthingManagerDao authingManagerDao;

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
     * 基础密码：session Token.
     */
    @Value("${authing.token.session.password}")
    private String authingTokenSessionPassword;

    /**
     * RSA公钥：Authing.
     */
    @Value("${rsa.authing.publicKey}")
    private String rsaAuthingPublicKey;

    /**
     * OneID隐私版本.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

    /**
     * token的盐值.
     */
    @Value("${authing.token.sha256.salt: }")
    private String tokenSalt;

    /**
     * 社区.
     */
    @Value("${community}")
    private String instanceCommunity;

    /**
     * 必须绑定手机号的社区.
     */
    @Value("${community.phone.number:openubmc,openfuyao}")
    private List<String> needPhoneNumberCommunity;

    /**
     * 静态日志记录器，用于记录 JwtTokenCreateService 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenCreateService.class);

    /**
     * 为 Authing 用户生成令牌.
     *
     * @param jwtCreatedParam jwt生成参数
     * @return tokens
     */
    @SneakyThrows
    public String[] authingUserToken(JwtCreatedParam jwtCreatedParam) {
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

        String username = jwtCreatedParam.getUsername();
        Boolean phoneExist = jwtCreatedParam.getPhoneExist();
        if (StringUtils.isBlank(username)
                || (!phoneExist && needPhoneNumberCommunity.contains(instanceCommunity))) {
            User user = authingManagerDao.getUserByUserId(jwtCreatedParam.getUserId());
            if (user != null) {
                if (StringUtils.isNotBlank(user.getUsername())) {
                    username = user.getUsername();
                }
                phoneExist = StringUtils.isNotBlank(user.getPhone());
            }
        }

        String headToken = JWT.create()
                .withAudience(username) //谁接受签名
                .withSubject(jwtCreatedParam.getUserId())
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(headTokenExpireAt) //过期时间
                .withJWTId(CommonUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                .sign(Algorithm.HMAC256(authingTokenBasePassword));
        String verifyToken = CommonUtil.encryptSha256(headToken, tokenSalt);
        redisDao.set("idToken_" + verifyToken, jwtCreatedParam.getIdToken(), expireSeconds);
        String permissionStr = Base64.getEncoder().encodeToString(jwtCreatedParam.getPermission()
                .getBytes(StandardCharsets.UTF_8));

        String token = JWT.create()
                .withAudience(jwtCreatedParam.getUserId()) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .withJWTId(CommonUtil.randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH))
                .withClaim("permission", permissionStr)
                .withClaim("inputPermission", jwtCreatedParam.getInputPermission())
                .withClaim("verifyToken", verifyToken)
                .withClaim("client_id", jwtCreatedParam.getAppId())
                .withClaim("oneidPrivacyAccepted", jwtCreatedParam.getOneidPrivacyVersionAccept())
                .withClaim("phoneExist", phoneExist)
                .sign(Algorithm.HMAC256(jwtCreatedParam.getPermission() + authingTokenSessionPassword));
        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            return new String[]{RSAUtil.publicEncrypt(token, publicKey), headToken};
        } catch (Exception e) {
            LOGGER.error("RSA Encrypt error {}", e.getMessage());
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
        Boolean phoneExist = false;
        if (claimMap.containsKey("phoneExist")) {
            phoneExist = claimMap.get("phoneExist").asBoolean();
        }
        String inputPermission = claimMap.get("inputPermission").asString();
        String permission = new String(Base64.getDecoder()
                .decode(claimMap.get("permission").asString()
                        .getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

        // 生成新的token和headToken
        List<String> audience = JWT.decode(headerJwtToken).getAudience();
        String username = ((audience == null) || audience.isEmpty()) ? "" : audience.get(0);
        return authingUserToken(new JwtCreatedParam(appId, userId, username, permission, inputPermission, idToken,
                oneidPrivacyVersion, phoneExist));
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
            LogUtil.createLogs(userId, "oidc token", "user",
                    "The user oidc token", null, "failed");
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
}
