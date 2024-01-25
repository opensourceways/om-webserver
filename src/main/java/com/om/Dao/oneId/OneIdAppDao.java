package com.om.Dao.oneId;

import com.alibaba.fastjson2.JSON;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import com.om.Result.Constant;
import kong.unirest.json.JSONObject;
import org.springframework.stereotype.Repository;

@Repository
public class OneIdAppDao {


    public OneIdEntity.App getAppInfo(String appId) throws Exception {
        String url = (OneIdConfig.API_HOST + Constant.ONEID_APP_ID_PATH).replace("{appId}", appId);
        HttpResponse<JsonNode> response = Unirest.get(url).header("Authorization", OneIdConfig.getManagementToken()).asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.App.class);
        }
        return null;
    }

    public OneIdEntity.App verifyAppSecret(String appId, String appSecret) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_APP_VERIFY_PATH;
        String body = String.format("{\"appId\":\"%s\",\"appSecret\":\"%s\"}", appId, appSecret);
        HttpResponse<JsonNode> response = Unirest.post(url)
                .header("Content-Type", "application/json")
                .header("Authorization", OneIdConfig.getManagementToken())
                .body(body)
                .asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.App.class);
        }
        return null;
    }

}
