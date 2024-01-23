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

package com.om.Dao;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import com.obs.services.ObsClient;
import com.obs.services.model.PutObjectResult;
import com.om.Modules.MessageCodeConfig;
import com.om.Modules.ServerErrorException;
import com.om.Result.Constant;
import com.om.Utils.CommonUtil;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;

import jakarta.annotation.PostConstruct;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@Repository
public class AuthingUserDao {
    private static final Logger logger =  LoggerFactory.getLogger(AuthingUserDao.class);
    
    @Value("${authing.userPoolId}")
    String userPoolId;

    @Value("${authing.secret}")
    String secret;

    @Value("${datastat.img.ak}")
    String datastatImgAk;

    @Value("${datastat.img.sk}")
    String datastatImgSk;

    @Value("${datastat.img.endpoint}")
    String datastatImgEndpoint;

    @Value("${datastat.img.bucket.name}")
    String datastatImgBucket;

    @Value("${social.extIdpId.github}")
    String socialExtIdpIdGithub;

    @Value("${social.identifier.github}")
    String socialIdentifierGithub;

    @Value("${social.authorizationUrl.github}")
    String socialAuthUrlGithub;

    @Value("${enterprise.extIdpId.gitee}")
    String enterExtIdpIdGitee;

    @Value("${enterprise.identifier.gitee}")
    String enterIdentifieGitee;

    @Value("${enterprise.authorizationUrl.gitee}")
    String enterAuthUrlGitee;

    @Value("${enterprise.extIdpId.openatom}")
    String enterExtIdpIdOpenatom;

    @Value("${enterprise.identifier.openatom}")
    String enterIdentifieOpenatom;

    @Value("${enterprise.authorizationUrl.openatom}")
    String enterAuthUrlOpenatom;

    @Value("${rsa.authing.privateKey}")
    String rsaAuthingPrivateKey;

    @Value("${username.reserved}")
    String usernameReserved;

    @Value("${datastat.img.default.photo}")
    String defaultPhoto;

    @Value("${datastat.img.photo.suffix}")
    String photoSuffix;

    @Value("${authing.api.host}")
    String authingApiHost;

    @Value("${authing.api.hostv2}")
    String authingApiHostV2;

    @Value("${authing.api.hostv3}")
    String authingApiHostV3;

    @Value("${aigc.privacy.version}")
    String aigcPrivacyVersion;

    @Value("${oneid.privacy.version}")
    String oneidPrivacyVersion;

    // -- temporary (解决gitee多身份源解绑问题) -- TODO
    @Value("${temp.extIdpIds}")
    String extIdpIds;
    @Value("${temp.identifiers}")
    String identifiers;
    @Value("${temp.users}")
    String users;
    // -- temporary -- TODO

    public static ManagementClient managementClient;

    public static ObsClient obsClient;

    private static List<String> reservedUsernames;

    public Map<String, AuthenticationClient> appClientMap;

    private List<String> photoSuffixes;

    @Autowired
    private RedisDao redisDao;

    @Autowired
    private Environment env;

    @PostConstruct
    public void init() {
        appClientMap = new HashMap<>();
        managementClient = new ManagementClient(userPoolId, secret);
        obsClient = new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint);
        reservedUsernames = getUsernameReserved();
        photoSuffixes = Arrays.asList(photoSuffix.split(";"));
    }

    public String sendPhoneCodeV3(String appId, String account, String channel) {
        String msg = "success";
        try {
            String phoneCountryCode = getPhoneCountryCode(account);
            account = getPurePhone(account);
            String body = String.format("{\"phoneNumber\": \"%s\",\"channel\": \"%s\",\"phoneCountryCode\": \"%s\"}", account, channel.toUpperCase(), phoneCountryCode);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + "/send-sms")
                    .header("x-authing-app-id", appId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");

            return msg;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return MessageCodeConfig.E0008.getMsgZh();
        }
    }

    public String sendEmailCodeV3(String appId, String account, String channel) {
        String msg = "success";
        try {
            String body = String.format("{\"email\": \"%s\",\"channel\": \"%s\"}", account, channel.toUpperCase());
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + "/send-email")
                    .header("x-authing-app-id", appId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");

            return msg;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return MessageCodeConfig.E0008.getMsgZh();
        }
    }

    // 邮箱验证码注册
    public String registerByEmailCode(String appId, String email, String code, String username) {
        String body = String.format("{\"connection\": \"PASSCODE\"," +
                "\"passCodePayload\": {\"email\": \"%s\",\"passCode\": \"%s\"}," +
                "\"profile\":{\"username\":\"%s\", \"givenName\":\"%s\"}}", email, code, username, oneidPrivacyVersion);
        return register(appId, body);
    }

    // 手机验证码注册
    public String registerByPhoneCode(String appId, String phone, String code, String username) {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"connection\": \"PASSCODE\"," +
                "\"passCodePayload\": {\"phone\": \"%s\",\"passCode\": \"%s\",\"phoneCountryCode\": \"%s\"}," +
                "\"profile\":{\"username\":\"%s\", \"givenName\":\"%s\"}}", phone, code, phoneCountryCode, username, oneidPrivacyVersion);
        return register(appId, body);
    }

    // 邮箱验密码注册
    public String registerByEmailPwd(String appId, String email, String password, String username) {
        String body = String.format("{\"connection\": \"PASSWORD\"," +
                "\"passwordPayload\": {\"email\": \"%s\",\"password\": \"%s\"}," +
                "\"profile\":{\"username\":\"%s\", \"givenName\":\"%s\"}," +
                "\"options\":{\"passwordEncryptType\":\"rsa\"}}", email, password, username, oneidPrivacyVersion);
        return register(appId, body);
    }

    // 手机密码注册
    public String registerByPhonePwd(String appId, String phone, String password, String username) {
        String body = String.format("{\"connection\": \"PASSWORD\"," +
                "\"passwordPayload\": {\"phone\": \"%s\",\"password\": \"%s\"}," +
                "\"profile\":{\"username\":\"%s\", \"givenName\":\"%s\"}," +
                "\"options\":{\"passwordEncryptType\":\"rsa\"}}", phone, password, username, oneidPrivacyVersion);
        return register(appId, body);
    }

    // 校验用户是否存在（用户名 or 邮箱 or 手机号）
    public boolean isUserExists(String appId, String account, String accountType) throws ServerErrorException {
        try {
            AuthenticationClient authentication = appClientMap.get(appId);
            switch (accountType.toLowerCase()) {
                case "username":
                    return authentication.isUserExists(account, null, null, null).execute();
                case "email":
                    return authentication.isUserExists(null, account, null, null).execute();
                case "phone":
                    return authentication.isUserExists(null, null, account, null).execute();
                default:
                    return true;
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            throw new ServerErrorException();
        }
    }

    public Object loginByEmailCode(Application app, String email, String code) throws ServerErrorException {
        String body = String.format("{\"connection\": \"PASSCODE\"," +
                "\"passCodePayload\": {\"email\": \"%s\",\"passCode\": \"%s\"}," +
                "\"options\": {\"autoRegister\": false}," +
                "\"client_id\":\"%s\",\"client_secret\":\"%s\"}", email, code, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    public Object loginByPhoneCode(Application app, String phone, String code) throws ServerErrorException {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"connection\": \"PASSCODE\"," +
                "\"passCodePayload\": {\"phone\": \"%s\",\"passCode\": \"%s\",\"phoneCountryCode\": \"%s\"}," +
                "\"options\": {\"autoRegister\": false}," +
                "\"client_id\":\"%s\",\"client_secret\":\"%s\"}", phone, code, phoneCountryCode, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    public Object loginByEmailPwd(Application app, String email, String password) throws ServerErrorException {
        if (!isUserExists(app.getId(), email, "email")) {
            return MessageCodeConfig.E00052.getMsgZh();
        }

        String body = String.format("{\"connection\": \"PASSWORD\"," +
                        "\"passwordPayload\": {\"email\": \"%s\",\"password\": \"%s\"}," +
                        "\"options\": {\"passwordEncryptType\": \"rsa\"}," +
                        "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                email, password, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    public Object loginByPhonePwd(Application app, String phone, String password) throws ServerErrorException {
        phone = getPurePhone(phone);

        if (!isUserExists(app.getId(), phone, "phone")) {
            return MessageCodeConfig.E00052.getMsgZh();
        }

        String body = String.format("{\"connection\": \"PASSWORD\"," +
                        "\"passwordPayload\": {\"phone\": \"%s\",\"password\": \"%s\"}," +
                        "\"options\": {\"passwordEncryptType\": \"rsa\"}," +
                        "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                phone, password, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    public Object loginByUsernamePwd(Application app, String username, String password) throws ServerErrorException {
        if (!isUserExists(app.getId(), username, "username")) {
            return MessageCodeConfig.E00052.getMsgZh();
        }

        String body = String.format("{\"connection\": \"PASSWORD\"," +
                        "\"passwordPayload\": {\"username\": \"%s\",\"password\": \"%s\"}," +
                        "\"options\": {\"passwordEncryptType\": \"rsa\"}," +
                        "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                username, password, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    public Application initAppClient(String appId) {
        Application app = getAppById(appId);
        if (app != null && !appClientMap.containsKey(appId)) {
            String appHost = "https://" + app.getIdentifier() + ".authing.cn";
            AuthenticationClient appClient = new AuthenticationClient(appId, appHost);
            appClient.setSecret(app.getSecret());
            appClientMap.put(appId, appClient);
        }
        return app;
    }

    public List<String> getAppRedirectUris(String appId) {
        List<String> redirectUris = new ArrayList<>();
        Application execute = getAppById(appId);
        if (execute != null)
            redirectUris = execute.getRedirectUris();
        return redirectUris;
    }

    public Application getAppById(String appId) {
        try {
            return managementClient.application().findById(appId).execute();
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }
    }

    public Map getUserInfoByAccessToken(String appId, String code, String redirectUrl) {
        try {
            AuthenticationClient authentication = appClientMap.get(appId);

            // code换access_token
            authentication.setRedirectUri(redirectUrl);
            Map res = (Map) authentication.getAccessTokenByCode(code).execute();
            String access_token = res.get("access_token").toString();

            // access_token换user
            Map user = (Map) authentication.getUserInfoByAccessToken(access_token).execute();
            user.put("id_token", res.get("id_token").toString());
            return user;
        } catch (Exception ex) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), ex);
            return null;
        }
    }

    public boolean logout(String appId, String idToken, String userId) {
        try {
            HttpResponse<JsonNode> response = Unirest.get(String.format(authingApiHost + "/logout?appId=%s&userId=%s", appId, userId))
                    .header("Authorization", idToken)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            int code = response.getBody().getObject().getInt("code");
            return code == 200;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return false;
        }
    }

    // 获取用户基本信息
    public User getUser(String userId) {
        try {
            return managementClient.users().detail(userId, true, true).execute();
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }
    }

    // 使用v3管理员接口获取用户信息
    public JSONObject getUserV3(String userId, String userIdType) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV3 + "/get-user")
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .queryString("userId", userId)
                    .queryString("userIdType", userIdType)
                    .queryString("withIdentities", true)
                    .asJson();
            return response.getBody().getObject().getJSONObject("data");
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }
    }

    public JSONObject getUserByName(String username) {
        try {
            User user = managementClient.users().find(new FindUserParam().withUsername(username)).execute();
            return getUserById(user.getId());
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }
    }

    // 获取用户基本信息
    public Object[] getAppUserInfo(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
        token = RSAUtil.privateDecrypt(token, privateKey);
        DecodedJWT decode = JWT.decode(token);
        String userId = decode.getAudience().get(0);
        String appId = decode.getClaim("client_id").asString();
        User user = getUser(userId);
        return new Object[]{appId, user};
    }

    // 获取用户详细信息
    public JSONObject getUserById(String userId) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV2 + "/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            return response.getBody().getObject().getJSONObject("data");
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }
    }
    
    // 更新用户邮箱
    public String updateEmailById(String userId, String email) {
        try {
            User res = managementClient.users().update(userId, new UpdateUserInput().withEmail(email)).execute();
            return res.getEmail();
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return "";
        }
    }

    // 删除用户
    public boolean deleteUserById(String userId) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.delete(authingApiHostV2 + "/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            int code = response.getBody().getObject().getInt("code");
            return code == 200;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return false;
        }
    }

    // 用户资源和操作权限
    public boolean checkUserPermission(String userId, String groupCode, String resourceCode, String resourceAction) {
        try {
            PaginatedAuthorizedResources pars = managementClient.users().listAuthorizedResources(userId, groupCode).execute();
            if (pars.getTotalCount() <= 0) {
                return false;
            }

            List<AuthorizedResource> ars = pars.getList();
            for (AuthorizedResource ar : ars) {
                String code = ar.getCode();
                if (code.equalsIgnoreCase(resourceCode)) {
                    List<String> actions = ar.getActions();
                    return actions != null && actions.size() != 0 && actions.contains(resourceAction);
                }
            }

            return false;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return false;
        }
    }

    // 用户资源和操作权限
    public ArrayList<String> getUserPermission(String userId, String groupCode) {
        ArrayList<String> pers = new ArrayList<>();
        try {
            PaginatedAuthorizedResources pars = managementClient.users().listAuthorizedResources(userId, groupCode).execute();
            if (pars.getTotalCount() <= 0) {
                return pers;
            }
            List<AuthorizedResource> ars = pars.getList();
            for (AuthorizedResource ar : ars) {
                List<String> actions = ar.getActions();
                pers.addAll(actions);
            }
            return pers;
        } catch (Exception e) {
//            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return pers;
        }
    }

    public boolean sendCode(String token, String account, String type, String field) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            AuthenticationClient authentication = appClientMap.get(appId);

            switch (type.toLowerCase()) {
                case "email":
                    String label = "";
                    if (field.equals("verify")) {
                        label = "VERIFY_EMAIL";
                    }
                    if (field.equals("change")) {
                        label = "CHANGE_EMAIL";
                    }
                    authentication.sendEmail(account, EmailScene.valueOfLabel(label)).execute();
                    break;
                case "phone":
                    authentication.sendSmsCode(account).execute();
                    break;
                default:
                    return false;
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return false;
        }
        return true;
    }

    public String getPublicKey() {
        String msg = MessageCodeConfig.E00048.getMsgEn();
        try {
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV3 + "/system").asJson();
            if (response.getStatus() == 200) {
                JSONObject resObj = response.getBody().getObject();
                resObj.remove("sm2");
                msg = resObj.toString();
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return msg;
    }

    public String updatePassword(String token, String oldPwd, String newPwd) {
        String msg = MessageCodeConfig.E00053.getMsgZh();
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];

            String body = String.format("{\"newPassword\": \"%s\"," +
                    "\"oldPassword\": \"%s\"," +
                    "\"passwordEncryptType\": \"rsa\"}", newPwd, oldPwd);
            HttpResponse<JsonNode> response = authPost("/update-password", appId, user.getToken(), body);
            JSONObject resObj = response.getBody().getObject();
            msg = resObj.getInt("statusCode") != 200 ? resObj.getString("message") : Constant.SUCCESS;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return msg;
    }

    public Object resetPwdVerifyEmail(String appId, String email, String code) {
        String body = String.format("{\"verifyMethod\": \"EMAIL_PASSCODE\"," +
                "\"emailPassCodePayload\": " +
                "{\"email\": \"%s\",\"passCode\": \"%s\"}}", email, code);
        return resetPwdVerify(appId, body);
    }

    public Object resetPwdVerifyPhone(String appId, String phone, String code) {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"verifyMethod\": \"PHONE_PASSCODE\"," +
                        "\"phonePassCodePayload\": " +
                        "{\"phoneNumber\": \"%s\",\"passCode\": \"%s\",\"phoneCountryCode\": \"%s\"}}",
                phone, code, phoneCountryCode);
        return resetPwdVerify(appId, body);
    }

    public String resetPwd(String pwdResetToken, String newPwd) {
        String msg = MessageCodeConfig.E00053.getMsgZh();
        try {
            String body = String.format("{\"passwordResetToken\": \"%s\"," +
                    "\"password\": \"%s\"," +
                    "\"passwordEncryptType\": \"rsa\"}", pwdResetToken, newPwd);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + "/reset-password")
                    .header("Content-Type", "application/json").body(body).asJson();
            JSONObject resObj = response.getBody().getObject();
            msg = resObj.getInt("statusCode") != 200 ? resObj.getString("message") : Constant.SUCCESS;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return msg;
    }

    public String updateAccount(String token, String oldAccount, String oldCode, String account, String code, String type) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User us = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(us);
            switch (type.toLowerCase()) {
                case "email":
                    authentication.updateEmail(account, code, oldAccount, oldCode).execute();
                    break;
                case "phone":
                    updatePhoneWithAuthingCode(oldAccount, oldCode, account, code, appId, us.getToken());
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return e.getMessage();
        }
        return "true";
    }

    public String unbindAccount(String token, String account, String type) {
        String resFail = "unbind fail";
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User us = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(us);

            if (StringUtils.isBlank(us.getEmail())) return "请先绑定邮箱";

            authentication.setCurrentUser(us);
            switch (type.toLowerCase()) {
                // TODO 目前不允许解绑邮箱
                /*case "email":
                    String email = us.getEmail();
                    if (!account.equals(email)) return resFail;
                    authentication.unbindEmail().execute();
                    break;*/
                case "phone":
                    String phone = us.getPhone();
                    if (!account.equals(phone)) return resFail;
                    authentication.unbindPhone().execute();
                    break;
                default:
                    return resFail;
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return e.getMessage();
        }
        return "unbind success";
    }

    public AuthenticationClient initUserAuthentication(String appId, User user) {
        initAppClient(appId);
        AuthenticationClient authentication = appClientMap.get(appId);
        authentication.setCurrentUser(user);
        return authentication;
    }

    public String bindAccount(AuthenticationClient authentication, String account, String code, String type) {
        try {
            switch (type.toLowerCase()) {
                case "email":
                    authentication.bindEmail(account, code).execute();
                    break;
                case "phone":
                    authentication.bindPhone(account, code).execute();
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            return e.getMessage();
        }
        return "true";
    }

    public String bindAccount(String token, String account, String code, String type) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(user);
            switch (type.toLowerCase()) {
                case "email":
                    String emailInDb = user.getEmail();
                    // situation: email is auto-generated
                    if (StringUtils.isNotBlank(emailInDb) && emailInDb.endsWith(Constant.AUTO_GEN_EMAIL_SUFFIX)) {
                        bindEmailWithSelfDistributedCode(authentication, user.getId(), account, code);
                    } else {
                        authentication.bindEmail(account, code).execute();
                    }
                    break;
                case "phone":
                    bindPhoneWithAuthingCode(account, code, appId, user.getToken());
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return e.getMessage();
        }
        return "true";
    }

    private void bindEmailWithSelfDistributedCode(
            AuthenticationClient authentication, String userId, String account, String code) throws Exception {
        String redisKey = account.toLowerCase() + "_CodeBindEmail";
        String codeTemp = (String) redisDao.get(redisKey);
        if (codeTemp == null) {
            throw new Exception("验证码无效或已过期");
        }
        if (!codeTemp.equals(code)) {
            throw new Exception("验证码不正确");
        }

        // check if email is bind to other account
        if (authentication.isUserExists(null, account, null, null).execute()) {
            throw new Exception("该邮箱已被其它账户绑定");
        }

        String res = updateEmailById(userId, account);

        if (res.equals(account)) {
            redisDao.remove(redisKey);
        } else {
            throw new Exception("服务异常");
        }
    }

    private void bindPhoneWithAuthingCode(String phone, String code, String appId, String token) throws Exception{
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"phoneNumber\": \"%s\"," +
            "\"passCode\": \"%s\"," +
            "\"phoneCountryCode\": \"%s\"}", 
            phone, code, phoneCountryCode);
        
        HttpResponse<JsonNode> response = authPost("/bind-phone", appId, token, body);
        JSONObject resObj = response.getBody().getObject();
        if (resObj.getInt("statusCode") != 200) {
            throw new Exception(resObj.getString("message"));
        }
    }

    private void updatePhoneWithAuthingCode(String oldPhone, String oldCode, String newPhone, String newCode,
            String appId, String token) throws Exception {
        String oldPhoneCountryCode = getPhoneCountryCode(oldPhone);
        oldPhone = getPurePhone(oldPhone);
        String newPhoneCountryCode = getPhoneCountryCode(newPhone);
        newPhone = getPurePhone(newPhone);

        String body = String.format("{\"verifyMethod\": \"PHONE_PASSCODE\"," +
            "\"phonePassCodePayload\": {" +
            "\"oldPhoneNumber\": \"%s\",\"oldPhonePassCode\": \"%s\",\"oldPhoneCountryCode\": \"%s\"," +
            "\"newPhoneNumber\": \"%s\",\"newPhonePassCode\": \"%s\",\"newPhoneCountryCode\": \"%s\"}}", 
            oldPhone, oldCode, oldPhoneCountryCode, newPhone, newCode, newPhoneCountryCode);
        
        HttpResponse<JsonNode> response = authPost("/verify-update-phone-request", appId, token, body);
        JSONObject resObj = response.getBody().getObject();
        if (resObj.getInt("statusCode") != 200) {
            throw new Exception(resObj.getString("message"));
        }

        Object reqObj = resObj.get("data");
        String reqToken = "";
        if (reqObj instanceof JSONObject) {
            JSONObject req = (JSONObject) reqObj;
            reqToken = req.getString("updatePhoneToken");
        } else {
            throw new Exception("服务异常");
        }
        applyUpdatePhoneToken(appId, token, reqToken);
    }

    private void applyUpdatePhoneToken(String appId, String userToken, String updatePhoneToken) throws Exception {
        String body = String.format("{\"updatePhoneToken\": \"%s\"}", updatePhoneToken);

        HttpResponse<JsonNode> response = authPost("/update-phone", appId, userToken, body);
        JSONObject resObj = response.getBody().getObject();
        if (resObj.getInt("statusCode") != 200) {
            throw new Exception(resObj.getString("message"));
        }
    }

    public List<Map<String, String>> linkConnList(String token) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(user);

            String userToken = user.getToken();
            List<Map<String, String>> list = new ArrayList<>();

            HashMap<String, String> mapGithub = new HashMap<>();
            String authGithub = String.format(socialAuthUrlGithub, socialIdentifierGithub, appId, userToken);
            mapGithub.put("name", "social_github");
            mapGithub.put("authorizationUrl", authGithub);

            HashMap<String, String> mapGitee = new HashMap<>();
            String authGitee = String.format(enterAuthUrlGitee, appId, enterIdentifieGitee, userToken);
            mapGitee.put("name", "enterprise_gitee");
            mapGitee.put("authorizationUrl", authGitee);

            HashMap<String, String> mapOpenatom = new HashMap<>();
            String authOpenatom = String.format(enterAuthUrlOpenatom, appId, enterIdentifieOpenatom, userToken);
            mapOpenatom.put("name", "enterprise_openatom");
            mapOpenatom.put("authorizationUrl", authOpenatom);

            list.add(mapGithub);
            list.add(mapGitee);
            list.add(mapOpenatom);
            return list;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }
    }

    public String linkAccount(String token, String secondToken) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User us = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(us);

            authentication.linkAccount(token, secondToken).execute();
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return e.getMessage();
        }
        return "true";
    }

    public String unLinkAccount(String token, String platform) {
        String msg = "解绑三方账号失败";
        String identifier;
        String extIdpId;
        try {
            switch (platform.toLowerCase()) {
                case "github":
                    identifier = socialIdentifierGithub;
                    extIdpId = socialExtIdpIdGithub;
                    break;
                case "gitee":
                    identifier = enterIdentifieGitee;
                    extIdpId = enterExtIdpIdGitee;
                    break;
                case "openatom":
                    identifier = enterIdentifieOpenatom;
                    extIdpId = enterExtIdpIdOpenatom;
                    break;
                default:
                    return msg;
            }

            Object[] appUserInfo = getAppUserInfo(token);
            User us = (User) appUserInfo[1];

            if (StringUtils.isBlank(us.getEmail())) return "请先绑定邮箱";

            // -- temporary (解决gitee多身份源解绑问题) -- TODO
            List<String> userIds = Stream.of(users.split(";")).collect(Collectors.toList());
            if (platform.toLowerCase().equals("gitee") && userIds.contains(us.getId())) {
                if (unLinkAccountTemp(us, identifiers, extIdpIds)) return "success";
                else return msg;
            } // -- temporary -- TODO

            String body = String.format("{\"identifier\":\"%s\",\"extIdpId\":\"%s\"}", identifier, extIdpId);
            Unirest.config().socketTimeout(0).connectTimeout(0);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV2 + "/users/identity/unlinkByUser")
                    .header("Authorization", us.getToken())
                    .header("x-authing-userpool-id", userPoolId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            if (response.getBody().getObject().getInt("code") == 200) msg = "success";
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return msg;
    }

    // -- temporary (解决gitee多身份源解绑问题) -- TODO
    public boolean unLinkAccountTemp(User us, String identifiers, String extIdpIds) {
        boolean flag = false;

        String[] split = identifiers.split(";");
        String[] split1 = extIdpIds.split(";");
        for (int i = 0; i < split.length; i++) {
            try {
                String body = String.format("{\"identifier\":\"%s\",\"extIdpId\":\"%s\"}", split[i], split1[i]);
                Unirest.config().socketTimeout(0).connectTimeout(0);
                HttpResponse<JsonNode> response = Unirest.post(authingApiHostV2 + "/users/identity/unlinkByUser")
                        .header("Authorization", us.getToken())
                        .header("x-authing-userpool-id", userPoolId)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .asJson();
                if (response.getBody().getObject().getInt("code") == 200) flag = true;
            } catch (Exception e) {
                logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            }
        }
        return flag;
    }

    public String updateUserBaseInfo(String token, Map<String, Object> map) throws ServerErrorException {
        String msg = "success";
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(user);

            UpdateUserInput updateUserInput = new UpdateUserInput();

            for (Map.Entry<String, Object> entry : map.entrySet()) {
                String item = entry.getKey();
                String inputValue = entry.getValue() == null ? "" : entry.getValue().toString();
                switch (item.toLowerCase()) {
                    case "nickname":
                        updateUserInput.withNickname(inputValue);
                        break;
                    case "company":
                        updateUserInput.withCompany(inputValue);
                        break;
                    case "username":
                        msg = checkUsername(appId, inputValue);
                        if (!msg.equals("success")) return msg;
                        if (StringUtils.isNotBlank(user.getUsername()) && !user.getUsername().startsWith("oauth2_"))
                            return "用户名唯一，不可修改";
                        updateUserInput.withUsername(inputValue);
                        break;
                    case "aigcprivacyaccepted":
                        if (aigcPrivacyVersion.equals(inputValue)) {
                            updateUserInput.withFormatted(aigcPrivacyVersion);
                        }
                        if ("revoked".equals(inputValue)) {
                            updateUserInput.withFormatted("revoked");
                        }
                        break;
                    case "oneidprivacyaccepted":
                        if (oneidPrivacyVersion.equals(inputValue)) {
                            updateUserInput.withGivenName(oneidPrivacyVersion);
                        }
                        if ("revoked".equals(inputValue)) {
                            updateUserInput.withGivenName("revoked");
                        }
                        break;
                    default:
                        break;
                }
            }
            authentication.updateProfile(updateUserInput).execute();
            return msg;
        } catch (ServerErrorException e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            throw e;
        } catch (Exception ex) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), ex);
            return MessageCodeConfig.E0007.getMsgZh();
        }
    }

    public boolean updatePhoto(String token, MultipartFile file) {
        InputStream inputStream = null;
        try {
            inputStream = CommonUtil.rewriteImage(file);

            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];
            AuthenticationClient authentication = appClientMap.get(appId);
            authentication.setCurrentUser(user);

            String photo = user.getPhoto();

            // 重命名文件
            String fileName = file.getOriginalFilename();
            for (String c : Constant.PHOTO_NOT_ALLOWED_CHARS.split(",")) {
                if (fileName.contains(c)) {
                    throw new Exception("Filename is invalid");
                }
            }
            String extension = fileName.substring(fileName.lastIndexOf("."));
            if (!photoSuffixes.contains(extension.toLowerCase())) {
                return false;
            }

            if (!CommonUtil.isFileContentTypeValid(file)) throw new Exception("File content type is invalid");

            String objectName = String.format("%s%s", UUID.randomUUID().toString(), extension);

            //上传文件到OBS
            PutObjectResult putObjectResult = obsClient.putObject(datastatImgBucket, objectName, inputStream);
            String objectUrl = putObjectResult.getObjectUrl();

            // 修改用户头像
            authentication.updateProfile(new UpdateUserInput().withPhoto(objectUrl)).execute();

            // 删除旧的头像
            deleteObsObjectByUrl(photo);
            return true;
        } catch (Exception ex) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), ex);
            return false;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    logger.error(e.getMessage());
                }
            }
        }
    }

    public void deleteObsObjectByUrl(String objectUrl) {
        try {
            if (StringUtils.isBlank(objectUrl)) return;

            int beginIndex = objectUrl.lastIndexOf("/");
            beginIndex = beginIndex == -1 ? 0 : beginIndex + 1;
            String objName = objectUrl.substring(beginIndex);
            if (obsClient.doesObjectExist(datastatImgBucket, objName) && !objName.equals(defaultPhoto))
                obsClient.deleteObject(datastatImgBucket, objName);
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
    }

    private String getManagementToken() {
        try {
            String body = String.format("{\"userPoolId\":\"%s\",\"secret\":\"%s\"}", userPoolId, secret);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV2 + "/userpools/access-token")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            return response.getBody().getObject().get("accessToken").toString();
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return "";
        }
    }

    public String checkUsername(String appId, String userName) throws ServerErrorException {
        String msg = "success";
        if (StringUtils.isBlank(userName))
            msg = "用户名不能为空";
        else if (!userName.matches(Constant.USERNAMEREGEX))
            msg = "请输入3到20个字符。只能由字母、数字或者下划线(_)组成。必须以字母开头，不能以下划线(_)结尾";
        else if (reservedUsernames.contains(userName) || isUserExists(appId, userName, "username"))
            msg = "用户名已存在";

        return msg;
    }

    public List<String> userAccessibleApps(String userId) {
        ArrayList<String> appIds = new ArrayList<>();
        try {
            String token = getUser(userId).getToken();
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV3 + "/get-my-accessible-apps")
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            if (response.getStatus() == 200) {
                JSONArray data = response.getBody().getObject().getJSONArray("data");
                for (Object item : data) {
                    if (item instanceof JSONObject) {
                        JSONObject app = (JSONObject) item;
                        appIds.add(app.getString("appId"));
                    }
                }
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return appIds;
    }

    private List<String> getUsernameReserved() {
        if (StringUtils.isBlank(usernameReserved)) return null;
        return Arrays.stream(usernameReserved.split(",")).map(String::trim).collect(Collectors.toList());
    }

    private String register(String appId, String body) {
        String msg = Constant.SUCCESS;
        try {
            HttpResponse<JsonNode> response = authPost("/signup", appId, body);
            JSONObject resObj = response.getBody().getObject();
            if (resObj.getInt("statusCode") != 200) {
                msg = resObj.getString("message");
            }
            return msg;
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return MessageCodeConfig.E00024.getMsgZh();
        }
    }

    private Object login(String appId, String body) {
        Object msg = MessageCodeConfig.E00027.getMsgZh();
        return authPostResData("/signin", appId, body, msg);
    }

    private Object resetPwdVerify(String appId, String body) {
        Object msg = MessageCodeConfig.E00012.getMsgZh();
        return authPostResData("/verify-reset-password-request", appId, body, msg);
    }

    private Object authPostResData(String uriPath, String appId, String body, Object defaultMsg) {
        Object msg = defaultMsg;
        try {
            HttpResponse<JsonNode> response = authPost(uriPath, appId, body);
            JSONObject resObj = response.getBody().getObject();
            msg = (resObj.getInt("statusCode") == 200)
                    ? resObj.get("data")
                    : resObj.getString("message");
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return msg;
    }


    private HttpResponse<JsonNode> authPost(String uriPath, String appId, String body)
            throws UnirestException {
        return Unirest.post(authingApiHostV3 + uriPath)
                .header("x-authing-app-id", appId)
                .header("Content-Type", "application/json")
                .body(body)
                .asJson();
    }

    private HttpResponse<JsonNode> authPost(String uriPath, String appId, String token,
                                            String body) throws UnirestException {
        return Unirest.post(authingApiHostV3 + uriPath)
                .header("Authorization", token)
                .header("x-authing-app-id", appId)
                .header("Content-Type", "application/json")
                .body(body)
                .asJson();
    }

    public String getPhoneCountryCode(String phone) {
        String phoneCountryCode = "+86";
        String[] countryCodes = env.getProperty("sms.international.countrys.code", "").split(",");
        for (String countryCode : countryCodes) {
            if (phone.startsWith(countryCode)) phoneCountryCode = countryCode;
        }
        return phoneCountryCode;
    }

    public String getPurePhone(String phone) {
        String[] countryCodes = env.getProperty("sms.international.countrys.code", "").split(",");
        for (String countryCode : countryCodes) {
            if (phone.startsWith(countryCode)) return phone.replace(countryCode, "");
        }
        return phone;
    }
}
