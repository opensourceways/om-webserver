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
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.*;
import com.om.Utils.CodeUtil;
import com.om.Utils.RSAUtil;
import com.om.Vo.TokenUser;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;


@Service
public class JwtTokenCreateService {
    @Autowired
    private openEuler openeuler;
    @Autowired
    private openGauss opengauss;
    @Autowired
    private openLookeng openlookeng;
    @Autowired
    private mindSpore mindspore;
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

    public String getToken(TokenUser user) {
        openComObject communityObj;
        switch (user.getCommunity().toLowerCase()) {
            case "openeuler":
                communityObj = openeuler;
                break;
            case "opengauss":
                communityObj = opengauss;
                break;
            case "openlookeng":
                communityObj = openlookeng;
                break;
            case "mindspore":
                communityObj = mindspore;
                break;
            default:
                return null;
        }

        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        int expireSeconds = Integer.parseInt(communityObj.getTokenExpireSeconds());
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        String basePassword = communityObj.getTokenBasePassword();

        return JWT.create()
                .withAudience(user.getUsername()) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .sign(Algorithm.HMAC256(user.getPassword() + basePassword));
    }

    public String[] authingUserToken(String userId, String permission, String inputPermission, String idToken) {
        // 过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        long expireSeconds = 60;
        try {
            expireSeconds = Integer.parseInt(authingTokenExpireSeconds);
        } catch (Exception e) {
            e.printStackTrace();
        }
        LocalDateTime expireDate = nowDate.plusSeconds(expireSeconds);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        String permissionStr = Base64.getEncoder().encodeToString(permission.getBytes());

        String verifyToken;
        try {
            verifyToken = new CodeUtil().randomStrBuilder(32);
        } catch (NoSuchAlgorithmException e) {
            verifyToken = RandomStringUtils.randomAlphanumeric(32);
            e.printStackTrace();
        }
        redisDao.set("idToken_" + verifyToken, idToken, expireSeconds);
        String perStr = "";
        ArrayList<String> pers = authingUserDao.getUserPermission(userId, env.getProperty("openeuler.groupCode"));
        for (String per : pers) {
            perStr += per + ",";
        }
        perStr = Base64.getEncoder().encodeToString(perStr.getBytes());

        String token = JWT.create()
                .withAudience(userId) //谁接受签名
                .withIssuedAt(issuedAt) //生成签名的时间
                .withExpiresAt(expireAt) //过期时间
                .withClaim("permission", permissionStr)
                .withClaim("inputPermission", inputPermission)
                .withClaim("verifyToken", verifyToken)
                .withClaim("permissionList", perStr)
                .sign(Algorithm.HMAC256(permission + authingTokenBasePassword));
        try {
            RSAPublicKey publicKey = RSAUtil.getPublicKey(rsaAuthingPublicKey);
            return new String[]{RSAUtil.publicEncrypt(token, publicKey), verifyToken};
        } catch (Exception e) {
            System.out.println("RSA Encrypt error");
            return new String[]{token, verifyToken};
        }
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
}
