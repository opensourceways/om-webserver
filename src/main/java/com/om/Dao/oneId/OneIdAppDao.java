package com.om.Dao.oneId;

import com.alibaba.fastjson2.JSON;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Result.Constant;
import org.json.JSONObject;
import org.springframework.stereotype.Repository;

@Repository
public class OneIdAppDao {


    public OneIdEntity.App getAppInfo(String appId) throws Exception {
        String url = (OneIdConfig.API_HOST + Constant.ONEID_APP_ID_PATH).replace("{appId}", appId);
        HttpResponse<JsonNode> response = Unirest.get(url).header("Authorization", OneIdConfig.getManagementToken()).asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.to(OneIdEntity.App.class, jsonObject);
        }
        return null;
    }

}
