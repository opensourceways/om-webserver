package com.om.Dao.oneId;

import com.alibaba.fastjson2.JSON;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import com.om.Result.Constant;
import kong.unirest.json.JSONObject;
import org.springframework.stereotype.Repository;

@Repository
public class OneIdThirdPartyUserDao {

    public OneIdEntity.ThirdPartyUser getThirdPartyUserByProvider(String provider, String userIdInIdp) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_THIRD_PARTY_USER_GET_PROVIDER_PATH;
        HttpResponse<JsonNode> response = Unirest.get(url)
                .header("Authorization",  OneIdConfig.getManagementToken())
                .queryString("provider", provider)
                .queryString("userIdInIdp", userIdInIdp)
                .asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.ThirdPartyUser.class);
        }
        return null;
    }

    public OneIdEntity.User createCompositeUser(OneIdEntity.User user) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_USER_C_PATH;
        HttpResponse<JsonNode> response = Unirest.post(url)
                .header("Content-Type", "application/json")
                .header("Authorization",  OneIdConfig.getManagementToken())
                .body(JSON.toJSONString(user))
                .asJson();
        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.User.class);
        }
        return null;
    }


    public OneIdEntity.User createThirdPartyUser(OneIdEntity.ThirdPartyUser user, String userId) throws Exception {
        String url = String.format(OneIdConfig.API_HOST + Constant.ONEID_THIRD_PARTY_USER_CREATE_PATH, userId);
        HttpResponse<JsonNode> response = Unirest.post(url)
                .header("Content-Type", "application/json")
                .header("Authorization",  OneIdConfig.getManagementToken())
                .body(JSON.toJSONString(user))
                .asJson();
        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.User.class);
        }
        return null;
    }

    public boolean deleteThirdPartyUser(String userId, String provider) throws Exception {
        String url = String.format(OneIdConfig.API_HOST + Constant.ONEID_THIRD_PARTY_USER_DELETE_PATH, userId);
        HttpResponse<JsonNode> response = Unirest.delete(url)
                .header("Content-Type", "application/json")
                .header("Authorization",  OneIdConfig.getManagementToken())
                .queryString("provider", provider)
                .asJson();
        if (response.getStatus() == 200) {
            return true;
        }
        return false;
    }
}
