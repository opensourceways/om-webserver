package com.om.provider.oauth2.impl;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Modules.UserIdentity;
import com.om.provider.oauth2.OidcProvider;
import org.json.JSONObject;
import org.springframework.stereotype.Repository;

@Repository("gitee")
public class GiteeProvider extends OidcProvider {
    @Override
    protected UserIdentity initUserIdentity(JSONObject userObj, String accessToken) {
        String email = getUserEmail(accessToken);

        return new UserIdentity()
                .setUserIdInIdp(getJsonValue(userObj, "id"))
                .setProvider(this.getName())
                .setUsername(getJsonValue(userObj, "login"))
                .setNickname(getJsonValue(userObj, "name"))
                .setPhoto(getJsonValue(userObj, "avatar_url"))
                .setEmail(email)
                .setBlog(getJsonValue(userObj, "blog"))
                .setWeibo(getJsonValue(userObj, "weibo"))
                .setAccessToken(accessToken);
    }

    /**
     * 获取用户邮箱
     *
     * @param accessToken access_token
     * @return email
     */
    public String getUserEmail(String accessToken) {
        String email = null;
        try {
            HttpResponse<JsonNode> res = Unirest.get(this.getEmailsEndpoint())
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .asJson();

            Object obj = res.getBody().getArray().get(0);
            if (obj instanceof JSONObject) {
                JSONObject o = (JSONObject) obj;
                email = o.getString("email");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return email;
    }
}
