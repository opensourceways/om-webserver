package com.om.provider.impl;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Modules.OauthProviderInfo;
import com.om.provider.Oauth2Provider;
import org.json.JSONObject;

public class OpenAtomProvider implements Oauth2Provider {
    @Override
    public String authorize(OauthProviderInfo providerInfo) {
        String authorizeUri = providerInfo.getAuthorizeUri();
        String clientId = providerInfo.getClientId();
        String callback = providerInfo.getCallback();
        String scope = providerInfo.getScope();
        String community = providerInfo.getCommunity();
        String permission = providerInfo.getPermission();
        String redirectUri = providerInfo.getRedirectUri();
//        return String.format("%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s?redirect_to=%s+%s+%s", authorizeUri, clientId, scope, callback, redirectUri, community, permission);
        return String.format("%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s", authorizeUri, clientId, scope, callback);
    }

    @Override
    public String getAccessToken(OauthProviderInfo providerInfo) {
        String tokenUri = providerInfo.getTokenUri();
        String clientId = providerInfo.getClientId();
        String clientSecret = providerInfo.getClientSecret();
        String callback = providerInfo.getCallback();
        String code = providerInfo.getCode();
        String format = String.format("%s?client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s", tokenUri, clientId, clientSecret, code, callback);
        try {
            HttpResponse<JsonNode> response = Unirest.post(format)
                    .header("Content-Type", "application/json")
                    .asJson();
            if (response.getStatus() != 200) return null;
            JSONObject object = response.getBody().getObject();
            String accessToken = object.getString("access_token");
            String refreshToken = object.getString("refresh_token");
            providerInfo.setAccessToken(accessToken);
            providerInfo.setRefreshToken(refreshToken);
            return accessToken;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public JSONObject getUser(OauthProviderInfo providerInfo) {
        String userUri = providerInfo.getUserUri();
        String accessToken = providerInfo.getAccessToken();
        String format = String.format("%s?access_token=%s", userUri, accessToken);
        try {
            HttpResponse<JsonNode> response = Unirest.get(format)
                    .header("Content-Type", "application/json")
                    .asJson();
            if (response.getStatus() != 200) return null;
            JSONObject object = response.getBody().getObject();
            JSONObject data = object.getJSONObject("data");
            return data;
        } catch (Exception e) {
            return null;
        }
    }
}
