package com.om.Service;

import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

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

    public ResponseEntity personalCenterUserInfo(String token) {
        try {
            String userId = getUserIdFromToken(token);
            JSONObject userObj = authingUserDao.getUserById(userId);
            HashMap<String, Object> userData = parseAuthingUser(userObj);
            // 返回结果
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }

    }

    public ResponseEntity deleteUser(String token) {
        String userId = getUserIdFromToken(token);
        boolean res = authingUserDao.deleteUserById(userId);
        if (res) return result(HttpStatus.OK, "delete user success", null);
        else return result(HttpStatus.UNAUTHORIZED, "delete user fail", null);
    }

    public ResponseEntity sendCode(String account, String type, String field) {
        boolean res = authingUserDao.sendCode(account, type, field);
        if (!res) {
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
        return result(HttpStatus.OK, "success", null);
    }

    // 未使用
    public ResponseEntity resetPassword(String account, String code, String ps, String type) {
        boolean res = authingUserDao.changePassword(account, code, ps, type);
        if (!res) {
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
        return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity updateAccount(String token, String oldaccount, String oldcode, String account, String code, String type) {
        String res = authingUserDao.updateAccount(token, oldaccount, oldcode, account, code, type);
        return message(res);
    }

    public ResponseEntity unbindAccount(String token, String type) {
        String res = authingUserDao.unbindAccount(token, type);
        return message(res);
    }

    public ResponseEntity bindAccount(String token, String account, String code, String type) {
        String res = authingUserDao.bindAccount(token, account, code, type);
        return message(res);
    }

    public ResponseEntity linkAccount(String token, String secondtoken) {
        String res = authingUserDao.linkAccount(token, secondtoken);
        return message(res);
    }

    public ResponseEntity unLinkAccount(String token, String platform) {
        String res = authingUserDao.unLinkAccount(token, platform);
        return message(res);
    }

    public ResponseEntity updateUserBaseInfo(String token, Map<String, Object> map) {
        boolean res = authingUserDao.updateUserBaseInfo(token, map);
        if (res) return result(HttpStatus.OK, "update base info success", null);
        else return result(HttpStatus.UNAUTHORIZED, "update base info fail", null);
    }

    public ResponseEntity updatePhoto(String token, MultipartFile file) {
        boolean res = authingUserDao.updatePhoto(token, file);
        if (res) return result(HttpStatus.OK, "update photo success", null);
        else return result(HttpStatus.UNAUTHORIZED, "update photo fail", null);
    }

    // 获取自定义token中的user id
    private String getUserIdFromToken(String token) {
        DecodedJWT decode = JWT.decode(token);
        return decode.getAudience().get(0);
    }

    // 解析authing user
    private HashMap<String, Object> parseAuthingUser(JSONObject userObj) {
        HashMap<String, Object> userData = new HashMap<>();

        userData.put("userName", jsonObjStringValue(userObj, "username"));
        userData.put("email", jsonObjStringValue(userObj, "email"));
        userData.put("phone", jsonObjStringValue(userObj, "phone"));
        userData.put("signedUp", jsonObjStringValue(userObj, "signedUp"));
        userData.put("nickName", jsonObjStringValue(userObj, "nickname"));
        userData.put("company", jsonObjStringValue(userObj, "company"));
        userData.put("photo", jsonObjStringValue(userObj, "photo"));
        ArrayList<Map<String, Object>> identities = authingUserIdentity(userObj);
        userData.put("identities", identities);

        return userData;
    }

    // identities 解析（包括gitee,github,wechat）
    private ArrayList<Map<String, Object>> authingUserIdentity(JSONObject userObj) {
        ArrayList<Map<String, Object>> res = new ArrayList<>();
        HashMap<String, Map<String, Object>> map = new HashMap<>();
        try {
            JSONArray jsonArray = userObj.getJSONArray("identities");
            for (Object o : jsonArray) {
                JSONObject obj = (JSONObject) o;
                authingUserIdentityIdp(obj, map);
            }
            res.addAll(map.values());
        } catch (Exception ex) {
            System.out.println("Identities Get Error");
        }
        return res;
    }

    // identities -> userInfoInIdp 解析（包括gitee,github,wechat）
    private void authingUserIdentityIdp(JSONObject identityObj, HashMap<String, Map<String, Object>> map) {
        HashMap<String, Object> res = new HashMap<>();

        JSONObject userInfoInIdpObj = identityObj.getJSONObject("userInfoInIdp");
        String accessToken = jsonObjStringValue(identityObj, "accessToken");
        String provider = jsonObjStringValue(identityObj, "provider");
        switch (provider) {
            case "github":
                String github_login = jsonObjStringValue(userInfoInIdpObj, "profile").replace("https://api.github.com/users/", "");
                res.put("identity", "github");
                res.put("login_name", github_login);
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "username"));
                res.put("accessToken", accessToken);
                map.put(provider, res);
                break;
            case "oauth2":
                String gitee_login = userInfoInIdpObj.getJSONObject("customData").getString("giteeLogin");
                res.put("identity", "gitee");
                res.put("login_name", gitee_login);
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "name"));
                res.put("accessToken", accessToken);
                map.put(provider, res);
                break;
            case "wechat":
                res.put("identity", "wechat");
                res.put("login_name", "");
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "nickname"));
                res.put("accessToken", accessToken);
                map.put(provider, res);
                break;
            default:
                break;
        }
    }

    // JSONObject获取单个node的值
    private String jsonObjStringValue(JSONObject jsonObj, String nodeName) {
        String res = "";
        try {
            if (jsonObj.isNull(nodeName)) return res;
            Object obj = jsonObj.get(nodeName);
            if (obj != null) res = obj.toString();
        } catch (Exception ex) {
            System.out.println(nodeName + "Get Error");
        }
        return res;
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        return new ResponseEntity<>(res, status);
    }

    private ResponseEntity message(String res) {
        switch (res) {
            case "true":
                return result(HttpStatus.OK, "success", null);
            case "false":
                return result(HttpStatus.BAD_REQUEST, "Account error", null);
            default:
                ObjectMapper objectMapper = new ObjectMapper();
                String message = "faild";
                try {
                    res = res.substring(14);
                    Iterator<JsonNode> buckets = objectMapper.readTree(res).iterator();
                    if (buckets.hasNext()) {
                        message = buckets.next().get("message").get("message").asText();                      
                    }
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                    message =  e.getMessage();
                }
                return result(HttpStatus.BAD_REQUEST, message, null);
        }
    }
}
