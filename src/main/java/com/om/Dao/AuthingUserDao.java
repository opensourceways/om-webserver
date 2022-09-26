package com.om.Dao;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.*;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

@Repository
public class AuthingUserDao {
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

    public static ManagementClient managementClient;

    public static AuthenticationClient authentication;

    @PostConstruct
    public void init() {
        managementClient = new ManagementClient(userPoolId, secret);
        authentication = new AuthenticationClient(omAppId, omAppHost);
        authentication.setSecret(omAppSecret);
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

    // 获取用户详细信息
    public JSONObject getUserById(String userId) {
        try {
            String token = getManagementToken();
            HttpResponse<JsonNode> response = Unirest.get("https://core.authing.cn/api/v2/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            return response.getBody().getObject().getJSONObject("data");
        } catch (Exception e) {
            System.out.println("User Get Error");
            return null;
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
            HttpResponse<JsonNode> response1 = Unirest.post("https://core.authing.cn/api/v2/users/login/session-status")
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

    private String getManagementToken() {
        try {
            String body = String.format("{\"userPoolId\":\"%s\",\"secret\":\"%s\"}", userPoolId, secret);
            HttpResponse<JsonNode> response = Unirest.post("https://core.authing.cn/api/v2/userpools/access-token")
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
