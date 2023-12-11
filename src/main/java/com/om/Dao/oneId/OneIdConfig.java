package com.om.Dao.oneId;

import com.alibaba.fastjson2.JSON;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Dao.RedisDao;
import com.om.Result.Constant;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;

@Configuration
public class OneIdConfig {

    public static String API_HOST;

    public static String USER_POOL_ID;

    public static String USER_POOL_SECRET;

    private final Environment environment;

    private static RedisDao redisDao;

    @Autowired
    public OneIdConfig(Environment environment) {
        this.environment = environment;
    }

    @Autowired
    public void setRedisDao(RedisDao redisDao) {
        OneIdConfig.redisDao = redisDao;
    }

    @PostConstruct
    public void init() {

        API_HOST = environment.getProperty("oneid.api.host");
        USER_POOL_ID = environment.getProperty("opengauss.pool.key");
        USER_POOL_SECRET = environment.getProperty("opengauss.pool.secret");
    }

    public static String getManagementToken() throws Exception {
        String mToken = (String)redisDao.get(Constant.ONEID_TOKEN_KEY);
        if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
            OneIdEntity.GetManagementToken managementToken = new OneIdEntity.GetManagementToken();
            managementToken.setAccessKeyId(USER_POOL_ID);
            managementToken.setAccessKeySecret(USER_POOL_SECRET);

            String url = API_HOST + Constant.ONEID_TOKEN_PATH;
            HttpResponse<JsonNode> response = Unirest.post(url).header("Content-Type", "application/json").body(JSON.toJSONString(managementToken)).asJson();

            if (response.getStatus() == 200) {
                // save token
                long oneIdExpire = Long.parseLong(Constant.ONEID_EXPIRE_SECOND);
                mToken = response.getBody().getObject().getString("data");
                redisDao.set(Constant.ONEID_TOKEN_KEY, mToken, oneIdExpire);

                // save rsa public key
                redisDao.set("Oneid-RSA-Public-Key", response.getHeaders().getFirst("RSA-Public-Key"), oneIdExpire);
            }
        }
        return mToken;
    }
}
