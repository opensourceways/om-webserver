/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.dao;

import cn.authing.core.types.Identity;

import com.om.result.Constant;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.json.JSONObject;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

/**
 * authing管理面接口.
 */
@Repository
public class AuthingManagerDao {
    /**
     * 日志打印.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingManagerDao.class);

    /**
     * 管理面接口鉴权.
     */
    private static final String MANAGEMENT_TOKEN_URI = "/get-management-token";

    /**
     * 解除三方绑定.
     */
    private static final String UNLINK_IDENTITY_URI = "/unlink-identity";

    /**
     * 绑定三方.
     */
    private static final String LINK_IDENTITY_URI = "/link-identity";

    /**
     * token多冗余10分钟，防止临界情况.
     */
    private static final Integer TOKEN_REDUNDANT_TIME = 600;

    /**
     * Authing 用户池 ID.
     */
    @Value("${authing.userPoolId}")
    private String userPoolId;

    /**
     * Authing 密钥.
     */
    @Value("${authing.secret}")
    private String secret;

    /**
     * Authing API v3 主机地址.
     */
    @Value("${authing.api.hostv3}")
    private String authingApiHostV3;

    /**
     * Redis 数据访问对象.
     */
    @Autowired
    private RedisDao redisDao;

    public String getManagementToken() {
        String token = "";
        try {
            String body = String.format("{\"accessKeyId\": \"%s\",\"accessKeySecret\": \"%s\"}", userPoolId, secret);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + MANAGEMENT_TOKEN_URI)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            JSONObject resObj = response.getBody().getObject();
            if (resObj.getInt("statusCode") != 200) {
                LOGGER.error("get authing manager token failed {}", resObj.getString("message"));
                return token;
            }
            JSONObject data = resObj.getJSONObject("data");
            if (data == null) {
                LOGGER.error("get authing manager token failed , data is null");
                return token;
            }
            token = data.getString("access_token");
            int expiresIn = data.getInt("expires_in");
            if (expiresIn <= TOKEN_REDUNDANT_TIME) {
                LOGGER.error("authing manager token expires_in invalid " + expiresIn);
                return token;
            }
            long oneidExpire = expiresIn - TOKEN_REDUNDANT_TIME;
            redisDao.set(Constant.REDIS_KEY_AUTH_MANAGER_TOKEN, token, oneidExpire);
        } catch (Exception e) {
            LOGGER.error("get authing manager token failed {}", e.getMessage());
        }
        return token;
    }

    /**
     * 解绑三方.
     *
     * @param identity 三方绑定信息
     * @return 是否解绑成功
     */
    public boolean removeIdentity(Identity identity) {
        try {
            String mToken = (String) redisDao.get(Constant.REDIS_KEY_AUTH_MANAGER_TOKEN);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken();
            }

            String body = String.format("{\"extIdpId\": \"%s\",\"userId\": \"%s\"}",
                    identity.getExtIdpId(), identity.getUserId());
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + UNLINK_IDENTITY_URI)
                    .header("Content-Type", "application/json")
                    .header("x-authing-userpool-id", userPoolId)
                    .header("authorization", mToken)
                    .body(body)
                    .asJson();
            JSONObject resObj = response.getBody().getObject();
            if (resObj.getInt("statusCode") != 200) {
                LOGGER.error("unbind identity failed {}", resObj.getString("message"));
                return false;
            }
        } catch (Exception e) {
            LOGGER.error("unbind identity failed {}", e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * 绑定三方.
     *
     * @param userId 用户名
     * @param identity 三方信息
     * @return 是否绑定成功
     */
    public boolean bindIdentity(String userId, Identity identity) {
        try {
            if (StringUtils.isBlank(userId) || identity == null) {
                return false;
            }
            String mToken = (String) redisDao.get(Constant.REDIS_KEY_AUTH_MANAGER_TOKEN);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken();
            }

            String body = String.format("{\"extIdpId\": \"%s\",\"userId\": \"%s\",\"type\": \"%s\""
                            + ",\"userIdInIdp\": \"%s\"}",
                    identity.getExtIdpId(), userId, identity.getType(), identity.getUserIdInIdp());
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + LINK_IDENTITY_URI)
                    .header("Content-Type", "application/json")
                    .header("x-authing-userpool-id", userPoolId)
                    .header("authorization", mToken)
                    .body(body)
                    .asJson();
            JSONObject resObj = response.getBody().getObject();
            if (resObj.getInt("statusCode") != 200) {
                LOGGER.error("bind identity failed {}", resObj.getString("message"));
                return false;
            }
        } catch (Exception e) {
            LOGGER.error("bind identity failed {}", e.getMessage());
            return false;
        }
        return true;
    }
}
