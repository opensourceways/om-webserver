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
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.mashape.unirest.request.body.MultipartBody;
import com.obs.services.ObsClient;
import com.obs.services.model.PutObjectResult;
import com.om.Modules.MessageCodeConfig;
import com.om.Utils.RSAUtil;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.PostConstruct;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Repository;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;


@Repository
public class AuthingUserDao {
    private final static String AUTHINGAPIHOST = "https://core.authing.cn";

    private final static String AUTHINGAPIHOST_V2 = AUTHINGAPIHOST + "/api/v2";

    private final static String AUTHINGAPIHOST_V3 = "https://api.authing.cn/api/v3";

    @Value("${authing.userPoolId}")
    String userPoolId;

    @Value("${authing.secret}")
    String secret;

    @Value("${authing.app.fuxi.id}")
    String omAppId;

    @Value("${authing.app.fuxi.host}")
    String omAppHost;

    @Value("${authing.app.fuxi.secret}")
    String omAppSecret;

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

    @Value("${rsa.authing.privateKey}")
    String rsaAuthingPrivateKey;


    @Value("${username.reserved}")
    String usernameReserved;

    // -- temporary (解决gitee多身份源解绑问题) -- TODO
    @Value("${temp.extIdpIds}")
    String extIdpIds;
    @Value("${temp.identifiers}")
    String identifiers;
    @Value("${temp.users}")
    String users;
    // -- temporary -- TODO

    public static ManagementClient managementClient;

    public static AuthenticationClient authentication;

    public static ObsClient obsClient;

    private static final String USERNAMEREGEX = "^[0-9a-zA-Z_]{3,20}$";

    private static List<String> reservedUsernames;

    @PostConstruct
    public void init() {
        managementClient = new ManagementClient(userPoolId, secret);
        authentication = new AuthenticationClient(omAppId, omAppHost);
        authentication.setSecret(omAppSecret);
        obsClient = new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint);
        reservedUsernames = getUsernameReserved();
    }

    public String sendPhoneCodeV3(String account, String channel) {
        String msg = "success";
        try {
            String body = String.format("{\"phoneNumber\": \"%s\",\"channel\": \"%s\"}", account, channel.toUpperCase());
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V3 + "/send-sms")
                    .header("x-authing-app-id", omAppId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");

            return msg;
        } catch (Exception e) {
            return "验证码发送失败";
        }
    }

    public String sendEmailCodeV3(String account, String channel) {
        String msg = "success";
        try {
            String body = String.format("{\"email\": \"%s\",\"channel\": \"%s\"}", account, channel.toUpperCase());
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V3 + "/send-email")
                    .header("x-authing-app-id", omAppId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");

            return msg;
        } catch (Exception e) {
            return "验证码发送失败";
        }
    }

    // 邮箱注册
    public String registerByEmail(String email, String code, String name) {
        String msg = "success";
        try {
            String body = String.format("{\"connection\": \"PASSCODE\",\"passCodePayload\": {\"email\": \"%s\",\"passCode\": \"%s\"},\"profile\":{\"username\":\"%s\"}}", email, code, name);
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V3 + "/signup")
                    .header("x-authing-app-id", omAppId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");

            return msg;
        } catch (Exception e) {
            return "注册失败";
        }

    }

    // 手机号注册
    public String registerByPhone(String phone, String code, String name) {
        String msg = "success";
        try {
            String body = String.format("{\"connection\": \"PASSCODE\",\"passCodePayload\": {\"phone\": \"%s\",\"passCode\": \"%s\"},\"profile\":{\"name\":\"%s\"}}", phone, code, name);
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V3 + "/signup")
                    .header("x-authing-app-id", omAppId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");

            return msg;
        } catch (Exception e) {
            return "注册失败";
        }
    }

    // 校验用户是否存在（用户名 or 邮箱 or 手机号）
    public boolean isUserExists(String account, String accountType) {
        try {
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
            return true;
        }
    }

    public Object loginByEmailCode(String email, String code) {
        String msg = "登录失败";
        try {
            if (!isUserExists(email, "email")) return "用户不存在";
            String body = String.format("{\"connection\": \"PASSCODE\",\"passCodePayload\": {\"email\": \"%s\",\"passCode\": \"%s\"},\"client_id\":\"%s\",\"client_secret\":\"%s\"}", email, code, omAppId, omAppSecret);
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V3 + "/signin")
                    .header("x-authing-app-id", omAppId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");
            else return resObj.get("data");
        } catch (Exception ignored) {
        }
        return msg;
    }

    public Object loginByPhoneCode(String phone, String code) {
        String msg = "登录失败";
        try {
            if (!isUserExists(phone, "phone")) return "用户不存在";
            String body = String.format("{\"connection\": \"PASSCODE\",\"passCodePayload\": {\"phone\": \"%s\",\"passCode\": \"%s\"},\"client_id\":\"%s\",\"client_secret\":\"%s\"}", phone, code, omAppId, omAppSecret);
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V3 + "/signin")
                    .header("x-authing-app-id", omAppId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) msg = resObj.getString("message");
            else return resObj.get("data");
        } catch (Exception ignored) {
        }

        return msg;
    }

    public List<String> getAppRedirectUris(String appId) {
        List<String> redirectUris = new ArrayList<>();
        try {
            Application execute = managementClient.application().findById(appId).execute();
            redirectUris = execute.getRedirectUris();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return redirectUris;
    }

    public HttpResponse<JsonNode> getAccessTokenByCode(String code, String appId, String grantType, String appSecret, String redirectUri) throws UnirestException {
        return Unirest.post(AUTHINGAPIHOST + "/oidc/token")
                .field("client_id", appId)
                .field("client_secret", appSecret)
                .field("grant_type", "authorization_code")
                .field("redirect_uri", redirectUri)
                .field("code", code)
                .asJson();
    }


    public HttpResponse<JsonNode> getUserByAccessToken(String accessToken) throws UnirestException {
        return Unirest.get(AUTHINGAPIHOST + "/oidc/me")
                .header("Authorization", accessToken)
                .asJson();
    }

    public Map getUserInfoByAccessToken(String code, String redirectUrl) {
        try {
            // code换access_token
            authentication.setRedirectUri(redirectUrl);
            Map res = (Map) authentication.getAccessTokenByCode(code).execute();
            String access_token = res.get("access_token").toString();

            // access_token换user
            Map user = (Map) authentication.getUserInfoByAccessToken(access_token).execute();
            user.put("id_token", res.get("id_token").toString());
            System.out.println("*** getAccessTokenByCode:" + res.get("id_token").toString());
            return user;
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public boolean logout(String idToken, String userId) {
        try {
            HttpResponse<JsonNode> response = Unirest.get(String.format(AUTHINGAPIHOST + "/logout?appId=%s&userId=%s", omAppId, userId))
                    .header("Authorization", idToken)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            int code = response.getBody().getObject().getInt("code");
            return code == 200;
        } catch (Exception e) {
            return false;
        }
    }

    // 获取用户基本信息
    public User getUser(String userId) {
        try {
            return managementClient.users().detail(userId, true, true).execute();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 获取用户基本信息
    public User getUserInfo(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
        token = RSAUtil.privateDecrypt(token, privateKey);
        DecodedJWT decode = JWT.decode(token);
        String userId = decode.getAudience().get(0);
        User user = getUser(userId);
        return user;
    }

    // 获取用户详细信息
    public JSONObject getUserById(String userId) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.get(AUTHINGAPIHOST_V2 + "/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            return response.getBody().getObject().getJSONObject("data");
        } catch (Exception e) {
            System.out.println("User Get Error");
            return null;
        }
    }

    // 删除用户
    public boolean deleteUserById(String userId) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.delete(AUTHINGAPIHOST_V2 + "/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            int code = response.getBody().getObject().getInt("code");
            return code == 200;
        } catch (Exception e) {
            e.printStackTrace();
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
            e.printStackTrace();
            return false;
        }
    }

    // TODO 此接口废弃 使用通过userID校验登录状态
    public boolean checkLoginStatusOnAuthing(User user) {
        try {
            authentication.setCurrentUser(user);
            JwtTokenStatus execute = authentication.checkLoginStatus().execute();
            return execute.getStatus();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // TODO 使用自己的个人中心后不再需要判断authing端的登录状态
    public boolean checkLoginStatusOnAuthing(String userId) {
        try {
            String token = getManagementToken();
            String loginStatusBody = String.format("{\"userId\":\"%s\",\"appId\":\"%s\"}", userId, omAppId);
            HttpResponse<JsonNode> response1 = Unirest.post(AUTHINGAPIHOST_V2 + "/users/login/session-status")
                    .header("Content-Type", "application/json")
                    .header("x-authing-userpool-id", userPoolId)
                    .header("authorization", token)
                    .body(loginStatusBody)
                    .asJson();

            return response1.getBody().getObject().getJSONObject("data").getBoolean("active");
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean sendCode(String account, String type, String field) {
        try {
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
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean changePassword(String account, String code, String newPassword, String type) {
        try {
            switch (type.toLowerCase()) {
                case "email":
                    authentication.resetPasswordByEmailCode(account, code, newPassword).execute();
                    break;
                case "phone":
                    authentication.resetPasswordByPhoneCode(account, code, newPassword).execute();
                    break;
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public String updateAccount(String token, String oldaccount, String oldcode, String account, String code, String type) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
            switch (type.toLowerCase()) {
                case "email":
                    authentication.updateEmail(account, code, oldaccount, oldcode).execute();
                    break;
                case "phone":
                    authentication.updatePhone(account, code, oldaccount, oldcode).execute();
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            return e.getMessage();
        }
        return "true";
    }

    public String unbindAccount(String token, String account, String type) {
        String resFail = "unbind fail";
        try {
            User us = getUserInfo(token);
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
            String message = e.getMessage();
            System.out.println(message);
            return message;
        }
        return "unbind success";
    }

    public String bindAccount(String token, String account, String code, String type) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
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

    public List<Map<String, String>> linkConnList(String token) {
        try {
            User user = getUserInfo(token);
            String userToken = user.getToken();
            List<Map<String, String>> list = new ArrayList<>();

            HashMap<String, String> mapGithub = new HashMap<>();
            String authGithub = String.format(socialAuthUrlGithub, socialIdentifierGithub, omAppId, userToken);
            mapGithub.put("name", "social_github");
            mapGithub.put("authorizationUrl", authGithub);

            HashMap<String, String> mapGitee = new HashMap<>();
            String authGitee = String.format(enterAuthUrlGitee, omAppId, enterIdentifieGitee, userToken);
            mapGitee.put("name", "enterprise_gitee");
            mapGitee.put("authorizationUrl", authGitee);

            list.add(mapGithub);
            list.add(mapGitee);
            return list;

            /*TODO 该接口因为Cookie参数获取不到，所以无法使用
            HttpResponse<JsonNode> response = Unirest.get(AUTHINGAPIHOST_V2 + "/users/identity/conn-list")
                    .header("Cookie", "")
                    .header("DNT", "1")
                    .header("x-authing-app-id", omAppId)
                    .header("x-authing-request-from", "userPortal")
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            JSONObject object = response.getBody().getObject();
            JSONArray jsonArray = response.getBody().getObject().getJSONObject("data").getJSONArray("list");*/
        } catch (Exception e) {
            return null;
        }
    }

    public String linkAccount(String token, String secondtoken) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
            authentication.linkAccount(token, secondtoken).execute();
        } catch (Exception e) {
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
                default:
                    return msg;
            }

            User us = getUserInfo(token);
            if (StringUtils.isBlank(us.getEmail())) return "请先绑定邮箱";

            // -- temporary (解决gitee多身份源解绑问题) -- TODO
            List<String> userIds = Stream.of(users.split(";")).collect(Collectors.toList());
            if (platform.toLowerCase().equals("gitee") && userIds.contains(us.getId())) {
                if (unLinkAccountTemp(us, identifiers, extIdpIds)) return "success";
                else return msg;
            } // -- temporary -- TODO

            String body = String.format("{\"identifier\":\"%s\",\"extIdpId\":\"%s\"}", identifier, extIdpId);
            Unirest.setTimeouts(0, 0);
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V2 + "/users/identity/unlinkByUser")
                    .header("Authorization", us.getToken())
                    .header("x-authing-userpool-id", userPoolId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            if (response.getBody().getObject().getInt("code") == 200) msg = "success";
        } catch (Exception e) {
            e.printStackTrace();
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
                Unirest.setTimeouts(0, 0);
                HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V2 + "/users/identity/unlinkByUser")
                        .header("Authorization", us.getToken())
                        .header("x-authing-userpool-id", userPoolId)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .asJson();
                if (response.getBody().getObject().getInt("code") == 200) flag = true;
            } catch (Exception ignored) {
            }
        }
        return flag;
    }

    public String updateUserBaseInfo(String token, Map<String, Object> map) {
        String msg = "success";
        try {
            User user = getUserInfo(token);
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
                        msg = checkUsername(inputValue);
                        if (!msg.equals("success")) return msg;
                        if (StringUtils.isNotBlank(user.getUsername())) return "用户名唯一，不可修改";
                        updateUserInput.withUsername(inputValue);
                        break;
                    default:
                        break;
                }
            }
            authentication.updateProfile(updateUserInput).execute();
            return msg;
        } catch (Exception ex) {
            return "更新失败";
        }
    }

    public boolean updatePhoto(String token, MultipartFile file) {
        try {
            User user = getUserInfo(token);
            authentication.setCurrentUser(user);

            // 重命名文件
            String fileName = file.getOriginalFilename();
            String extension = fileName.substring(fileName.lastIndexOf("."));
            String objectName = String.format("%s-%s%s", user.getId(), DigestUtils.md5DigestAsHex(fileName.getBytes()), extension);

            //上传文件到OBS
            PutObjectResult putObjectResult = obsClient.putObject(datastatImgBucket, objectName, file.getInputStream());
            String objectUrl = putObjectResult.getObjectUrl();

            // 修改用户头像
            authentication.updateProfile(new UpdateUserInput().withPhoto(objectUrl)).execute();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private String getManagementToken() {
        try {
            String body = String.format("{\"userPoolId\":\"%s\",\"secret\":\"%s\"}", userPoolId, secret);
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST_V2 + "/userpools/access-token")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            return response.getBody().getObject().get("accessToken").toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String checkUsername(String userName) {
        String msg = "success";
        if (StringUtils.isBlank(userName))
            msg = "用户名不能为空";
        else if (!userName.matches(USERNAMEREGEX))
            msg = "请输入3到20个字符，由字母、数字、下划线(_)组成";
        else if (reservedUsernames.contains(userName) || isUserExists(userName, "username"))
            msg = "用户名已存在";

        return msg;
    }

    private List<String> getUsernameReserved() {
        if (StringUtils.isBlank(usernameReserved)) return null;
        return Arrays.stream(usernameReserved.split(",")).map(String::trim).collect(Collectors.toList());
    }

    public Map<String, MessageCodeConfig> getErrorCode() {
        HashMap<String, MessageCodeConfig> map = new HashMap<>();
        map.put("验证码已失效", MessageCodeConfig.E0001);
        map.put("验证码无效或已过期", MessageCodeConfig.E0001);
        map.put("验证码不正确", MessageCodeConfig.E0002);
        map.put("该手机号已被绑定", MessageCodeConfig.E0003);
        map.put("该邮箱已被绑定", MessageCodeConfig.E0004);
        map.put("Duplicate entry", MessageCodeConfig.E0004);
        map.put("没有配置其他登录方式", MessageCodeConfig.E0005);
        map.put("解绑三方账号失败", MessageCodeConfig.E0006);
        map.put("更新失败", MessageCodeConfig.E0007);
        map.put("验证码发送失败", MessageCodeConfig.E0008);
        map.put("一分钟之内已发送过验证码", MessageCodeConfig.E0009);
        map.put("注销用户失败", MessageCodeConfig.E00010);
        map.put("旧手机号非用户账号绑定的手机号", MessageCodeConfig.E00011);
        map.put("请求异常", MessageCodeConfig.E00012);
        map.put("新邮箱和旧邮箱一样", MessageCodeConfig.E00013);
        map.put("新手机号和旧手机号一样", MessageCodeConfig.E00014);
        map.put("已绑定手机号", MessageCodeConfig.E00015);
        map.put("已绑定邮箱", MessageCodeConfig.E00016);
        map.put("退出登录失败", MessageCodeConfig.E00017);
        map.put("用户名不能为空", MessageCodeConfig.E00018);
        map.put("用户名已存在", MessageCodeConfig.E00019);
        map.put("手机号或者邮箱不能为空", MessageCodeConfig.E00020);
        map.put("请输入正确的手机号或者邮箱", MessageCodeConfig.E00021);
        map.put("该账号已注册", MessageCodeConfig.E00022);
        map.put("请求过于频繁", MessageCodeConfig.E00023);
        map.put("注册失败", MessageCodeConfig.E00024);
        map.put("该手机号 1 分钟内已发送过验证码", MessageCodeConfig.E00025);
        map.put("验证码已失效，请重新获取验证码", MessageCodeConfig.E00026);
        map.put("登录失败", MessageCodeConfig.E00027);
        map.put("mobile number every day exceeds the upper limit", MessageCodeConfig.E00028);
        map.put("仅登录和注册使用", MessageCodeConfig.E00029);
        map.put("失败次数过多，请稍后重试", MessageCodeConfig.E00030);
        map.put("新邮箱与已绑定邮箱相同", MessageCodeConfig.E00031);
        map.put("新手机号与已绑定手机号相同", MessageCodeConfig.E00032);
        map.put("用户名唯一，不可修改", MessageCodeConfig.E00033);
        map.put("用户不存在", MessageCodeConfig.E00034);
        map.put("回调地址与配置不符", MessageCodeConfig.E00035);
        map.put("请指定应用的id、secret、host", MessageCodeConfig.E00036);
        map.put("授权失败", MessageCodeConfig.E00037);
        map.put("请先绑定邮箱", MessageCodeConfig.E00038);
        map.put("邮箱不能为空", MessageCodeConfig.E00039);
        map.put("请输入正确的邮箱", MessageCodeConfig.E00040);

        return map;
    }
}
