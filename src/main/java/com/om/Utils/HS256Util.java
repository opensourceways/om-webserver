package com.om.Utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Result.Constant;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Objects;

import static com.om.Utils.CodeUtil.randomStrBuilder;
import static com.om.config.LoginConfig.OIDC_ACCESS_TOKEN_EXPIRE;

@Component
public final class HS256Util {

    private static String HS256Key;

    private static String loginPage;

    /**
     * HS256密钥
     */
    @Value("${token.base.password}")
    private String hs256Key;

    /**
     * oidc域名
     */
    @Value("${oidc.login.page}")
    private String oidcPage;

    @PostConstruct
    public void init() {
        HS256Key = hs256Key;
        loginPage = oidcPage;
    }

    private static final Logger logger =  LoggerFactory.getLogger(HS256Util.class);

    public static String getHS256Token(OneIdEntity.User user){
        // 计算签发时间与过期时间
        LocalDateTime nowDate = LocalDateTime.now();
        Date issuedAt = Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant());
        long accessTokenExpire = OIDC_ACCESS_TOKEN_EXPIRE;
        LocalDateTime expireDate = nowDate.plusSeconds(accessTokenExpire);
        Date expireAt = Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant());

        if (Objects.isNull(HS256Key)) {
            logger.error("invalid HS256 key!");
            return null;
        }
        String HS256 = null;
        try {
            //Nonce
            String nonce = randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH);
            HS256 = JWT.create()
                    .withIssuer(loginPage)
                    .withSubject(user.getId())
                    .withAudience(user.getId()) //谁接受签名
                    .withIssuedAt(issuedAt) //生成签名的时间
                    .withExpiresAt(expireAt) //过期时间
                    .withClaim("nonce", nonce)    //载荷
                    .sign(Algorithm.HMAC256(HS256Key));
        } catch (Exception e) {
            logger.error("init hs256 fail!" + e.getMessage());
        }
        return HS256;
    }
}
