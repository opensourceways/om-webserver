package com.om.Dao;

import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.AuthorizedResource;
import cn.authing.core.types.PaginatedAuthorizedResources;
import cn.authing.core.types.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.util.List;

@Repository
public class AuthingUserDao {
    @Value("${authing.userPoolId}")
    String userPoolId;

    @Value("${authing.secret}")
    String secret;


    public User getUser(String userId) {
        try {
            ManagementClient managementClient = new ManagementClient(userPoolId, secret);
            return managementClient.users().detail(userId, true, true).execute();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean checkUserPermission(String userId, String groupCode, String resourceCode, String resourceAction) {
        try {
            ManagementClient managementClient = new ManagementClient(userPoolId, secret);
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
}
