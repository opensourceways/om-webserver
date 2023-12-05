package com.om.Dao;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Result.Constant;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

@Repository
public class OneidAppDao {

    @Value("${oneid.api.host}")
    String apiHost;

    @Autowired
    private RedisDao redisDao;

    public String getManagementToken(String poolId, String poolSecret) {
        String token = "";
        try {
            String body = String.format("{\"accessKeyId\": \"%s\",\"accessKeySecret\": \"%s\"}", poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.post(apiHost + Constant.ONEID_TOKEN_PATH)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            if (response.getStatus() == 200) {
                // save token
                long oneidExpire = Long.parseLong(Constant.ONEID_EXPIRE_SECOND);
                token = response.getBody().getObject().getString("data");
                redisDao.set(Constant.ONEID_TOKEN_KEY, token, oneidExpire);

                // save rsa public key
                redisDao.set("Oneid-RSA-Public-Key", response.getHeaders().getFirst("RSA-Public-Key"), oneidExpire);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return token;
    }

    private static final Logger logger = LoggerFactory.getLogger(OneidAppDao.class);

    public JSONObject getApp(String poolId, String poolSecret, String appId) throws Exception {
        JSONObject app = null;

        String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
        if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
            mToken = getManagementToken(poolId, poolSecret);
        }

        HttpResponse<JsonNode> response = Unirest.get(apiHost + Constant.ONEID_APP_ID_PATH.replace("{appId}", appId))
                .header("Authorization", mToken)
                .asJson();

        if (response.getStatus() == 200) {
            app = response.getBody().getObject().getJSONObject("data");
        }
        return app;
    }

}
