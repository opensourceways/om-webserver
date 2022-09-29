package com.om.Dao;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.obs.services.ObsClient;
import com.obs.services.model.PutObjectResult;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

@Repository
public class AuthingUserDao {
    private final static String AUTHINGAPIHOST = "https://core.authing.cn/api/v2";

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


    public static ManagementClient managementClient;

    public static AuthenticationClient authentication;

    public static ObsClient obsClient;

    @PostConstruct
    public void init() {
        managementClient = new ManagementClient(userPoolId, secret);
        authentication = new AuthenticationClient(omAppId, omAppHost);
        authentication.setSecret(omAppSecret);
        obsClient = new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint);
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
            return user;
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
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
    public User getUserInfo(String token) {
        DecodedJWT decode = JWT.decode(token);
        String userId = decode.getAudience().get(0);
        User user = getUser(userId);
        return user;
    }

    // 获取用户详细信息
    public JSONObject getUserById(String userId) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.get(AUTHINGAPIHOST + "/users/" + userId)
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
            HttpResponse<JsonNode> response = Unirest.delete(AUTHINGAPIHOST + "/users/" + userId)
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

    public boolean checkLoginStatusOnAuthing(String userId) {
        try {
            String token = getManagementToken();
            String loginStatusBody = String.format("{\"userId\":\"%s\",\"appId\":\"%s\"}", userId, omAppId);
            HttpResponse<JsonNode> response1 = Unirest.post(AUTHINGAPIHOST + "/users/login/session-status")
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

    public boolean updateAccount(String token, String account, String code, String type) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
            switch (type.toLowerCase()) {
                case "email":
                    authentication.updateEmail(account, code).execute();
                    break;
                case "phone":
                    authentication.updatePhone(account, code).execute();
                    break;
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public boolean unbindAccount(String token, String type) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
            System.out.println(us.getEmail());
            switch (type.toLowerCase()) {
                case "email":
                    authentication.unbindEmail().execute();
                    break;
                case "phone":
                    authentication.unbindPhone().execute();
                    break;
                default:
                    return false;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
        return true;
    }

    public boolean bindAccount(String token, String account, String code, String type) {
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
                    return false;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
        return true;
    }

    public boolean linkAccount(String token, String secondtoken) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
            authentication.linkAccount(token, secondtoken).execute();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
        return true;
    }

    public boolean unLinkAccount(String token, String platform) {
        try {
            User us = getUserInfo(token);
            authentication.setCurrentUser(us);
            UnLinkAccountParam unlink = new UnLinkAccountParam(token, ProviderType.valueOf(platform));
            authentication.unLinkAccount(unlink).execute();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
        return true;
    }

    public boolean updateUserBaseInfo(String token, Map<String, Object> map) {
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
                    default:
                        break;
                }
            }
            authentication.updateProfile(updateUserInput).execute();
            return true;
        } catch (Exception ex) {
            return false;
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
            HttpResponse<JsonNode> response = Unirest.post(AUTHINGAPIHOST + "/userpools/access-token")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            return response.getBody().getObject().get("accessToken").toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}
