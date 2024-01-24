package com.om.Dao.oneId;

import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Repository;

import com.alibaba.fastjson2.JSON;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Result.Constant;

@Repository
public class OneIdThirdPartyDao {

    public List<OneIdEntity.ThirdPartyClient> getAllClientsByAppId(String appId) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_THIRD_PARTY_ASSOCIATION_PATH;
        HttpResponse<JsonNode> response = Unirest.get(url)
            .header("Authorization", OneIdConfig.getManagementToken())
            .queryString("appId", appId)
            .asJson();

        if (response.getStatus() == 200) {
            JSONArray jsonArray = response.getBody().getObject().getJSONArray("data");
            return JSON.parseArray(jsonArray.toString(), OneIdEntity.ThirdPartyClient.class);
        }
        return null;
    }

    public OneIdEntity.ThirdPartyClient getClientByAssociation(String appId, String connId) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_THIRD_PARTY_ASSOCIATION_PATH;
        HttpResponse<JsonNode> response = Unirest.get(url)
            .header("Authorization", OneIdConfig.getManagementToken())
            .queryString("appId", appId)
            .queryString("socialIdentitySourceId", connId)
            .asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONArray("data").getJSONObject(0);
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.ThirdPartyClient.class);
        }
        return null;
    }

    public OneIdEntity.ThirdPartyClient getClientById(String connId) throws Exception {
        String url = String.format(OneIdConfig.API_HOST + Constant.ONEID_THIRD_PARTY_CLIENT_GET_PATH, connId);
        HttpResponse<JsonNode> response = Unirest.get(url)
            .header("Authorization", OneIdConfig.getManagementToken())
            .asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.ThirdPartyClient.class);
        }
        return null;
    }

}