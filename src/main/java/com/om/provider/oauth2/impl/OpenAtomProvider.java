package com.om.provider.oauth2.impl;

import com.om.Modules.UserIdentity;
import com.om.provider.oauth2.OidcProvider;
import org.json.JSONObject;
import org.springframework.stereotype.Repository;

@Repository("openatom")
public class OpenAtomProvider extends OidcProvider {
    @Override
    protected UserIdentity initUserIdentity(JSONObject userObj, String accessToken) {
        JSONObject data = userObj.getJSONObject("data");
        return new UserIdentity()
                .setUserIdInIdp(getJsonValue(data, "userId"))
                .setProvider(this.getName())
                .setNickname(getJsonValue(data, "nickName"))
                .setPhoto(getJsonValue(data, "headImageUrl"))
                .setEmail(getJsonValue(data, "email"))
                .setPhone(getJsonValue(data, "phone"))
                .setAccessToken(accessToken);
    }
}
