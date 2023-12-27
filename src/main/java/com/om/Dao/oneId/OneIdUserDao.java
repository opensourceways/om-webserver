package com.om.Dao.oneId;

import com.alibaba.fastjson2.JSON;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Result.Constant;
import org.json.JSONObject;
import org.springframework.stereotype.Repository;

@Repository
public class OneIdUserDao {

    public OneIdEntity.User loginByPassword(String account, String accountType, String password) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_CHECK_PASSWORD_PATH.replace("{account}", account);

        HttpResponse<JsonNode> response = Unirest.get(url)
                .header("Authorization",  OneIdConfig.getManagementToken())
                .queryString("userIdType", accountType)
                .queryString("password", password)
                .asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.User.class);
        }
        return null;
    }

    public OneIdEntity.User getUserInfo(String account, String accountType) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_USER_URD_PATH.replace("{account}", account);

        HttpResponse<JsonNode> response = Unirest.get(url)
                .header("Authorization", OneIdConfig.getManagementToken())
                .queryString("userIdType", accountType)
                .asJson();

        if (response.getStatus() == 200) {
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("data");
            return JSON.parseObject(jsonObject.toString(), OneIdEntity.User.class);
        }
        return null;
    }

    public JSONObject getUserInfoToObj(String account, String accountType) throws Exception {
        String url = OneIdConfig.API_HOST + Constant.ONEID_USER_URD_PATH.replace("{account}", account);

        HttpResponse<JsonNode> response = Unirest.get(url)
                .header("Authorization", OneIdConfig.getManagementToken())
                .queryString("userIdType", accountType)
                .asJson();

        if (response.getStatus() == 200) {
            return response.getBody().getObject().getJSONObject("data");
        }
        return null;
    }
}
