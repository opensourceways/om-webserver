package com.om.Dao;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.graphql.GraphQLException;
import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import java.io.IOException;
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
            // 初始化
//            AuthenticationClient authentication = new AuthenticationClient(omAppId, omAppHost);
//            authentication.setSecret(omAppSecret);

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

    public User getUser(String userId) {
        try {
//            ManagementClient managementClient = new ManagementClient(userPoolId, secret);
            return managementClient.users().detail(userId, true, true).execute();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean checkUserPermission(String userId, String groupCode, String resourceCode, String resourceAction) {
        try {
//            ManagementClient managementClient = new ManagementClient(userPoolId, secret);
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
}
