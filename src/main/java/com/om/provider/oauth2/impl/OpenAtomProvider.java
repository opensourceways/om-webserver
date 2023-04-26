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
                .setUserIdInIdp(data.get("userId"))
                .setNickname(data.get("nickName"))
                .setPhoto(data.get("headImageUrl"))
                .setEmail(data.get("email"))
                .setPhone(data.get("phone"))
                .setAccessToken(accessToken);
    }
}
