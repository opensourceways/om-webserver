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

import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.AuthorizedResource;
import cn.authing.core.types.FindUserParam;
import cn.authing.core.types.Identity;
import cn.authing.core.types.PaginatedAuthorizedResources;
import cn.authing.core.types.UpdateUserInput;
import cn.authing.core.types.User;
import jakarta.annotation.PostConstruct;

import com.om.modules.MessageCodeConfig;
import com.om.result.Constant;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Repository;
import org.springframework.util.CollectionUtils;

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
     * Authing API v2 主机地址.
     */
    @Value("${authing.api.hostv2}")
    private String authingApiHostV2;

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

    /**
     * Spring 环境对象.
     */
    @Autowired
    private Environment env;

    /**
     * Authing 用户管理客户端实例.
     */
    private ManagementClient managementClient;

    /**
     * 在类实例化后立即执行的初始化方法.
     */
    @PostConstruct
    public void init() {
        this.managementClient = new ManagementClient(userPoolId, secret);
    }

    /**
     * 获取管理面token.
     * @return token.
     */
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
            if (resObj.getInt("statusCode") != HttpStatus.OK.value()) {
                LOGGER.error("bind identity failed {}", resObj.getString("message"));
                return false;
            }
        } catch (Exception e) {
            LOGGER.error("bind identity failed {}", e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * 获取管理面token.
     * @return token.
     */
    public String getManagementTokenV2() {
        try {
            String body = String.format("{\"userPoolId\":\"%s\",\"secret\":\"%s\"}", userPoolId, secret);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV2 + "/userpools/access-token")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            return response.getBody().getObject().get("accessToken").toString();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return "";
        }
    }

    /**
     * 使用v3管理员接口获取用户信息.
     *
     * @param userId     用户 ID
     * @param userIdType 用户 ID 类型
     * @return 返回包含用户信息的 JSONObject 对象，如果获取失败则返回 null
     */
    public JSONObject getUserV3(String userId, String userIdType) {
        try {
            String token = getManagementTokenV2();
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV3 + "/get-user")
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .queryString("userId", userId)
                    .queryString("userIdType", userIdType)
                    .queryString("withIdentities", true)
                    .asJson();
            return response.getBody().getObject().getJSONObject("data");
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

        /**
     * 根据用户 ID 获取用户详细信息.
     *
     * @param userId 用户 ID
     * @return 返回包含用户信息的 JSONObject 对象，如果未找到用户则返回 null
     */
    public JSONObject getUserById(String userId) {
        try {
            String token = getManagementTokenV2();
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV2 + "/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            return response.getBody().getObject().getJSONObject("data");
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

    /**
     * 通过用户 ID 删除用户.
     *
     * @param userId 用户 ID
     * @return 如果成功删除用户则返回 true，否则返回 false
     */
    public boolean deleteUserById(String userId) {
        try {
            String token = getManagementTokenV2();
            HttpResponse<JsonNode> response = Unirest.delete(authingApiHostV2 + "/users/" + userId)
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            int code = response.getBody().getObject().getInt("code");
            return code == 200;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return false;
        }
    }

    /**
     * 通过用户名获取用户信息.
     *
     * @param username 用户名
     * @return 返回包含用户信息的 JSONObject 对象，如果未找到用户则返回 null
     */
    public JSONObject getUserByName(String username) {
        try {
            User user = managementClient.users().find(new FindUserParam().withUsername(username)).execute();
            return getUserById(user.getId());
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

    /**
     * 根据邮箱查询用户id.
     *
     * @param email 电子邮箱
     * @return 用户id
     */
    public String getUserIdByEmail(String email) {
        try {
            User user = managementClient.users().find(new FindUserParam().withEmail(email)).execute();
            if (user == null) {
                return null;
            }
            return user.getId();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

    /**
     * 根据手机号查询用户id.
     *
     * @param phone 手机号
     * @return 用户id
     */
    public String getUserIdByPhone(String phone) {
        try {
            phone = getPurePhone(phone);
            User user = managementClient.users().find(new FindUserParam().withPhone(phone)).execute();
            if (user == null) {
                return null;
            }
            return user.getId();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

    /**
     * 获取电话号码的纯净形式，去除任何非数字字符.
     *
     * @param phone 原始电话号码
     * @return 返回经过处理后的纯净电话号码
     */
    public String getPurePhone(String phone) {
        String[] countryCodes = env.getProperty("sms.international.countrys.code", "").split(",");
        for (String countryCode : countryCodes) {
            if (phone.startsWith(countryCode)) {
                return phone.replace(countryCode, "");
            }
        }
        return phone;
    }

    /**
     * 将用户踢出系统.
     *
     * @param userId 用户ID
     * @return 如果成功将用户踢出系统则返回 true，否则返回 false
     */
    public boolean kickUser(String userId) {
        try {
            List<String> userIds = new ArrayList<>();
            userIds.add(userId);
            return managementClient.users().kick(userIds).execute();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return false;
        }
    }

    /**
     * 通过用户ID更新用户的电子邮件地址.
     *
     * @param userId 用户 ID
     * @param email  要更新为的电子邮件地址
     * @return 返回更新后的电子邮件地址，如果更新成功则返回新的电子邮件地址，否则返回null
     */
    public String updateEmailById(String userId, String email) {
        try {
            User res = managementClient.users().update(userId, new UpdateUserInput().withEmail(email)).execute();
            return res.getEmail();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return "";
        }
    }

    /**
     * 获取用户资源和操作权限.
     *
     * @param userId    用户 ID
     * @param groupCode 用户组code
     * @return 返回用户在指定用户组下的权限列表，作为一个字符串数组列表
     */
    public ArrayList<String> getUserPermission(String userId, String groupCode) {
        ArrayList<String> pers = new ArrayList<>();
        try {
            PaginatedAuthorizedResources pars = managementClient
                    .users()
                    .listAuthorizedResources(userId, groupCode)
                    .execute();
            if (pars.getTotalCount() <= 0) {
                return pers;
            }
            List<AuthorizedResource> ars = pars.getList();
            for (AuthorizedResource ar : ars) {
                List<String> actions = ar.getActions();
                if (!CollectionUtils.isEmpty(actions)) {
                    pers.addAll(actions);
                }
            }
            return pers;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return pers;
        }
    }
}
