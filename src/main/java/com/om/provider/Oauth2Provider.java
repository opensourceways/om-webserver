package com.om.provider;

import com.om.Modules.OauthProviderInfo;
import org.json.JSONObject;

public interface Oauth2Provider {
    String authorize(OauthProviderInfo providerInfo);
    String getAccessToken(OauthProviderInfo providerInfo);
    JSONObject getUser(OauthProviderInfo providerInfo);
}
