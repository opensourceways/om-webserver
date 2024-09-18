package com.om.Utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Modules.MessageCodeConfig;
import com.om.Service.AuthingService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Arrays;

@Component
public class AuthingUtil {

    /**
     * 使用 @Autowired 注解注入环境变量.
     */
    @Autowired
    private Environment env;

    /**
     * 静态变量: LOGGER - 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingService.class);

    /**
     * 获取自定义token中的user id.
     *
     * @param token
     * @return String
     */
    public String getUserIdFromToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException {
        DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
        return decode.getAudience().get(0);
    }

    /**
     * 解密RSA加密过的token.
     *
     * @param token
     * @return String
     */
    public String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
        return RSAUtil.privateDecrypt(token, privateKey);
    }

    /**
     * 解析 Authing 用户方法.
     *
     * @param userObj 用户对象
     * @return HashMap 包含用户信息的哈希表
     */
    public HashMap<String, Object> parseAuthingUser(JSONObject userObj) {
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("username", jsonObjStringValue(userObj, "username"));
        userData.put("email", jsonObjStringValue(userObj, "email"));
        userData.put("phone", jsonObjStringValue(userObj, "phone"));
        userData.put("phoneCountryCode", jsonObjStringValue(userObj, "phoneCountryCode"));
        userData.put("signedUp", jsonObjStringValue(userObj, "signedUp"));
        userData.put("nickname", jsonObjStringValue(userObj, "nickname"));
        userData.put("company", jsonObjStringValue(userObj, "company"));
        userData.put("photo", jsonObjStringValue(userObj, "photo"));
        ArrayList<Map<String, Object>> identities = authingUserIdentity(userObj);
        userData.put("identities", identities);
        return userData;
    }

    /**
     * identities 解析（包括gitee,github,wechat）.
     *
     * @param userObj 用户对象
     * @return ArrayList
     */
    public ArrayList<Map<String, Object>> authingUserIdentity(JSONObject userObj) {
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
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", ex.getMessage());
        }
        return res;
    }

    /**
     * identities -> userInfoInIdp 解析（包括gitee,github,wechat）.
     *
     * @param identityObj 用户对象
     * @param map map
     */
    public void authingUserIdentityIdp(JSONObject identityObj, HashMap<String, Map<String, Object>> map) {
        HashMap<String, Object> res = new HashMap<>();
        JSONObject userInfoInIdpObj = identityObj;
        // 三方账号直接合并到用户已有账号，无三方账号详细用户信息
        if (identityObj.has("userInfoInIdp") && !identityObj.isNull("userInfoInIdp")) {
            userInfoInIdpObj = identityObj.getJSONObject("userInfoInIdp");
        }
        String userIdInIdp = identityObj.getString("userIdInIdp");
        res.put("userIdInIdp", userIdInIdp);
        String extIdpId = identityObj.getString("extIdpId");

        if (extIdpId.equals(env.getProperty("social.extIdpId.github"))) {
            String target = env.getProperty("github.users.api");
            target = (Objects.isNull(target) ? "" : target);
            String githubLogin = jsonObjStringValue(userInfoInIdpObj, "profile").replace(target, "");
            res.put("identity", "github");
            res.put("login_name", convertIdentityName(githubLogin));
            res.put("user_name", convertIdentityName(jsonObjStringValue(userInfoInIdpObj, "username")));
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("github", res);
        } else if (extIdpId.equals(env.getProperty("enterprise.extIdpId.gitee"))) {
            res.put("identity", "gitee");
            if (userInfoInIdpObj.has("customData")) {
                String giteeLogin = userInfoInIdpObj.getJSONObject("customData").getString("giteeLogin");
                res.put("login_name", convertIdentityName(giteeLogin));
                res.put("user_name", convertIdentityName(userInfoInIdpObj
                        .getJSONObject("customData").getString("giteeName")));
            } else {
                res.put("login_name", convertIdentityName(jsonObjStringValue(userInfoInIdpObj, "name")));
                res.put("user_name", convertIdentityName(jsonObjStringValue(userInfoInIdpObj, "username")));
            }
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("gitee", res);
        } else if (extIdpId.equals(env.getProperty("enterprise.extIdpId.openatom"))) {
            String phone = jsonObjStringValue(userInfoInIdpObj, "phone");
            String email = jsonObjStringValue(userInfoInIdpObj, "email");
            String name = StringUtils.isNotBlank(email) ? email : phone;
            res.put("identity", "openatom");
            res.put("login_name", convertIdentityName(name));
            res.put("user_name", convertIdentityName(name));
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("openatom", res);
        } else if (extIdpId.equals(env.getProperty("social.extIdpId.wechat"))) {
            String name = jsonObjStringValue(userInfoInIdpObj, "nickname");
            res.put("identity", "wechat");
            res.put("login_name", convertIdentityName(name));
            res.put("user_name", convertIdentityName(name));
            res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
            map.put("wechat", res);
        }
    }

    private String convertIdentityName(String userName) {
        return StringUtils.isBlank(userName) ? "_" : userName;
    }

    /**
     * JSONObject获取单个node的值.
     * @param jsonObj jsonObj
     * @param nodeName nodeName
     * @return String
     */
    public String jsonObjStringValue(JSONObject jsonObj, String nodeName) {
        String res = "";
        try {
            if (jsonObj.isNull(nodeName)) {
                return res;
            }
            Object obj = jsonObj.get(nodeName);
            if (obj != null) {
                res = obj.toString();
            }
        } catch (Exception ex) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", ex.getMessage());
        }
        return res;
    }

    /**
     * JSONObject获取单个node的值.
     * @param jsonObj jsonObj
     * @param nodeName nodeName
     * @return object
     */
    public Object jsonObjObjectValue(JSONObject jsonObj, String nodeName) {
        Object res = null;
        try {
            if (jsonObj.isNull(nodeName)) {
                return res;
            }
            Object obj = jsonObj.get(nodeName);
            if (obj != null) {
                res = obj;
            }
        } catch (Exception ex) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", ex.getMessage());
        }
        return res;
    }

    /**
     * 获取cookie.
     *
     * @param request 请求体
     * @param cookieName cookie名
     * @return cookie
     */
    public Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie cookie = null;
        try {
            Cookie[] cookies = request.getCookies();
            cookie = getCookie(cookies, cookieName);
        } catch (Exception ignored) {
        }
        return cookie;
    }

    /**
     * 获取cookie.
     *
     * @param cookies 所有cookie
     * @param cookieName cookie名
     * @return 返回的cookie
     */
    private Cookie getCookie(Cookie[] cookies, String cookieName) {
        Cookie cookie = null;
        try {
            cookie = Arrays.stream(cookies).filter(cookieEle ->
                    cookieEle.getName().equals(cookieName)).findFirst().orElse(null);
        } catch (Exception ignored) {
        }
        return cookie;
    }

    /**
     * 解析oidc支持的scope.
     *
     * @return scope map
     */
    public HashMap<String, String> oidcScopeAuthingMapping() {
        String[] mappings = env.getProperty("oidc.scope.authing.mapping", "").split(",");
        HashMap<String, String> authingMapping = new HashMap<>();
        for (String mapping : mappings) {
            if (StringUtils.isBlank(mapping)) {
                continue;
            }
            String[] split = mapping.split(":");
            authingMapping.put(split[0], split[1]);
        }
        return authingMapping;
    }

    /**
     * 解析oidc支持的scope.
     *
     * @return 其他的scope map
     */
    public HashMap<String, String[]> getOidcScopesOther() {
        String[] others = env.getProperty("oidc.scope.other", "").split(";");
        HashMap<String, String[]> otherMap = new HashMap<>();
        for (String other : others) {
            if (StringUtils.isBlank(other)) {
                continue;
            }
            String[] split = other.split("->");
            otherMap.put(split[0], split[1].split(","));
        }
        return otherMap;
    }
}
