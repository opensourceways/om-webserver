/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.modules.MessageCodeConfig;
import com.om.service.AuthingService;
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
        JSONObject userInfoInIdpObj = identityObj.getJSONObject("userInfoInIdp");
        String userIdInIdp = identityObj.getString("userIdInIdp");
        res.put("userIdInIdp", userIdInIdp);
        String originConnId = identityObj.getJSONArray("originConnIds").get(0).toString();
        if (originConnId.equals(env.getProperty("social.connId.github"))) {
            String target = env.getProperty("github.users.api");
            target = (Objects.isNull(target) ? "" : target);
            String githubLogin = jsonObjStringValue(userInfoInIdpObj, "profile").replace(target, "");
            res.put("identity", "github");
            res.put("login_name", githubLogin);
            res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "username"));
            map.put("github", res);
        } else if (originConnId.equals(env.getProperty("enterprise.connId.gitee"))) {
            res.put("identity", "gitee");
            if (userInfoInIdpObj.has("customData")) {
                String giteeLogin = userInfoInIdpObj.getJSONObject("customData").getString("giteeLogin");
                res.put("login_name", giteeLogin);
                res.put("user_name", userInfoInIdpObj.getJSONObject("customData").getString("giteeName"));
            } else {
                res.put("login_name", jsonObjStringValue(userInfoInIdpObj, "name"));
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "username"));
            }
            map.put("gitee", res);
        } else if (originConnId.equals(env.getProperty("enterprise.connId.openatom"))) {
            String phone = jsonObjStringValue(userInfoInIdpObj, "phone");
            String email = jsonObjStringValue(userInfoInIdpObj, "email");
            String name = StringUtils.isNotBlank(email) ? email : phone;
            res.put("identity", "openatom");
            res.put("login_name", name);
            res.put("user_name", name);
            map.put("openatom", res);
        } else if (originConnId.equals(env.getProperty("social.connId.wechat"))) {
            String name = jsonObjStringValue(userInfoInIdpObj, "nickname");
            res.put("identity", "wechat");
            res.put("login_name", name);
            res.put("user_name", name);
            map.put("wechat", res);
        }
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
}
