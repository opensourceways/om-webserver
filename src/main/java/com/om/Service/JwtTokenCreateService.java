package com.om.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.om.Modules.*;
import com.om.Vo.TokenUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

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
}
