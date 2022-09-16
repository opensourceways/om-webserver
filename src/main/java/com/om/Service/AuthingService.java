package com.om.Service;

import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AuthingService {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    public ResponseEntity authingUserPermission(String community, String token) {
        try {
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            String permissionTemp = decode.getClaim("permission").asString();
            String inputPermission = decode.getClaim("inputPermission").asString();

            // 资源权限验证
            String permissionToken = new String(Base64.getDecoder().decode(permissionTemp.getBytes()));
            ArrayList<String> permissions = new ArrayList<>();
            String[] split = permissionToken.split("->");
            boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
            if (hasActionPer) {
                permissions.add(inputPermission);
            }

            // 获取用户
            User user = authingUserDao.getUser(userId);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", user.getPhoto());
            userData.put("permissions", permissions);
            userData.put("username", user.getUsername());
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    public ResponseEntity logout(String token) {
        try {
            DecodedJWT decode = JWT.decode(token);
            String idToken = decode.getClaim("subject").asString();
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();
            String redisKey = userId + issuedAt.toString();
            boolean set = redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));
            if (set) {
                System.out.println(userId + " logout success");
            }

            HashMap<String, Object> userData = new HashMap<>();
            userData.put("id_token", idToken);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }


    public ResponseEntity tokenApply(String community, String code, String permission, String redirectUrl) {
        try {
            // 将URL中的中文转码，因为@RequestParam会自动解码，而我们需要未解码的参数
            String url = redirectUrl;
            Matcher matcher = Pattern.compile("[\\u4e00-\\u9fa5]+").matcher(redirectUrl);
            String tmp = "";
            while (matcher.find()) {
                tmp = matcher.group();
                System.out.println(tmp);
                url = url.replaceAll(tmp, URLEncoder.encode(tmp, "UTF-8"));
            }

            // 通过code获取access_token，再通过access_token获取用户
            // Map user = authingUserDao.getUserInfoByAccessToken(code, URLDecoder.decode(redirectUrl, "UTF-8"));
            Map user = authingUserDao.getUserInfoByAccessToken(code, url);
            if (user == null) return result(HttpStatus.UNAUTHORIZED, "user not found", null);
            String userId = user.get("sub").toString();
            String idToken = user.get("id_token").toString();
            String picture = user.get("picture").toString();
            String username = user.get("username").toString();

            // 资源权限
            String permissionInfo = env.getProperty(community + "." + permission);

            // 生成token
            String token = jwtTokenCreateService.authingUserToken(userId, permissionInfo, permission, idToken);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", token);
            userData.put("photo", picture);
            userData.put("username", username);
            return result(HttpStatus.OK, "success", userData);

        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        return new ResponseEntity<>(res, status);
    }

}
