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

import cn.authing.core.http.HttpCall;
import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.AuthorizedResource;
import cn.authing.core.types.AuthorizedTargetsParam;
import cn.authing.core.types.FindUserParam;
import cn.authing.core.types.IResourceResponse;
import cn.authing.core.types.Identity;
import cn.authing.core.types.PaginatedAuthorizedResources;
import cn.authing.core.types.Pagination;
import cn.authing.core.types.ResourcePermissionAssignment;
import cn.authing.core.types.ResourceType;
import cn.authing.core.types.RestfulResponse;
import cn.authing.core.types.UpdateUserInput;
import cn.authing.core.types.User;
import jakarta.annotation.PostConstruct;

import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.controller.bean.response.IdentityInfo;
import com.om.controller.bean.response.UserOfResourceInfo;
import com.om.modules.MessageCodeConfig;
import com.om.result.Constant;
import com.om.service.PrivacyHistoryService;
import com.om.utils.AuthingUtil;
import com.om.utils.RSAUtil;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.json.JSONObject;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.Collectors;

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
     * 允许的社区列表.
     */
    private List<String> allowedCommunity;

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
     * Authing 的 RSA 私钥.
     */
    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;
    /**
     * OneID 隐私版本号.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;
    /**
     * 应用程序版本号.
     */
    @Value("${app.version:1.0}")
    private String appVersion;
    /**
     * 社区名称.
     */
    @Value("${community}")
    private String community;

    /**
     * Redis 数据访问对象.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 使用 @Autowired 注解注入authingUtil.
     */
    @Autowired
    private AuthingUtil authingUtil;

    /**
     * Spring 环境对象.
     */
    @Autowired
    private Environment env;

    /**
     * 历史隐私记录保存类.
     */
    @Autowired
    private PrivacyHistoryService privacyHistoryService;

    /**
     * Authing 用户管理客户端实例.
     */
    private static ManagementClient managementClient;

     /**
     * 客户端实例赋值.
     *
     * @param managementClient 客户端实例
     */
    public static void setInitManagementClient(ManagementClient managementClient) {
        AuthingManagerDao.managementClient = managementClient;
    }

    /**
     * 在类实例化后立即执行的初始化方法.
     */
    @PostConstruct
    public void init() {
        setInitManagementClient(new ManagementClient(userPoolId, secret));
        allowedCommunity = Arrays.asList(Constant.OPEN_EULER, Constant.MIND_SPORE, Constant.MODEL_FOUNDRY,
                Constant.OPEN_UBMC);
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
     * 根据用户ID获取用户基本信息.
     *
     * @param userId 用户ID
     * @return 返回对应用户ID的用户对象，如果不存在则返回null
     */
    public User getUserByUserId(String userId) {
        try {
            return managementClient.users().detail(userId, true, true).execute();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
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
    public User getUserByName(String username) {
        try {
            User user = managementClient.users().find(new FindUserParam().withUsername(username)).execute();
            return user;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

     /**
     * 更新用户信息.
     *
     * @param userId 用户名
     * @param updateUserInput 用户信息
     * @throws IOException 异常
     */
    public void updateUserInfo(String userId, UpdateUserInput updateUserInput) throws IOException {
        managementClient.users().update(userId, updateUserInput).execute();
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
     * 获取权限空间下所有资源.
     *
     * @param nameSpaceCode 权限空间
     * @param page 分页
     * @param limit 数量限制
     * @return 资源列表
     */
    public List<String> listResources(String nameSpaceCode, Integer page, Integer limit) {
        try {
            HttpCall<RestfulResponse<Pagination<IResourceResponse>>, Pagination<IResourceResponse>> call =
                    managementClient.acl().listResources(nameSpaceCode, ResourceType.DATA, limit, page);
            Pagination<IResourceResponse> pageResponse = call.execute();
            List<IResourceResponse> list = pageResponse.getList();
            return list.stream().map(i -> i.getCode()).collect(Collectors.toList());
        } catch (Exception e) {
            LOGGER.error("get resource list failed {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * 获取某个资源的具备权限的用户.
     *
     * @param nameSpaceCode 权限空间
     * @param resource 资源
     * @return 用户权限列表
     */
    public List<UserOfResourceInfo> listUserOfResource(String nameSpaceCode, String resource) {
        try {
            List<UserOfResourceInfo> resList = new ArrayList<>();
            AuthorizedTargetsParam param =
                    new AuthorizedTargetsParam(nameSpaceCode, ResourceType.DATA, resource);
            List<ResourcePermissionAssignment> sourceList = managementClient.acl().getAuthorizedTargets(param)
                    .execute().getList();
            if (CollectionUtils.isEmpty(sourceList)) {
                return resList;
            }
            List<String> userIds = sourceList.stream()
                    .map(ResourcePermissionAssignment::getTargetIdentifier).collect(Collectors.toList());
            List<User> users = managementClient.users().batch(userIds).execute();
            HashMap<String, List<IdentityInfo>> identityBeanMap = new HashMap<>();
            for (User user : users) {
                identityBeanMap.put(user.getId(), authingUtil.parseUserIdentity(user.getIdentities()));
            }
            for (ResourcePermissionAssignment assignment : sourceList) {
                String userId = assignment.getTargetIdentifier();
                List<String> actions = assignment.getActions();
                UserOfResourceInfo userOfResourceInfo = new UserOfResourceInfo();
                userOfResourceInfo.setUserId(userId);
                userOfResourceInfo.setActions(actions);
                userOfResourceInfo.setIdentityInfos(identityBeanMap.get(userId));
                resList.add(userOfResourceInfo);
            }
            return resList;
        } catch (Exception e) {
            LOGGER.error("get user resources failed {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * 撤销用户隐私设置.
     *
     * @param userId 用户ID
     * @return 如果成功撤销用户隐私设置则返回 true，否则返回 false
     */
    public boolean revokePrivacy(String userId) {
        try {
            // get user
            User user = managementClient.users().detail(userId, false, false).execute();
            UpdateUserInput input = new UpdateUserInput();
            input.withGivenName(updatePrivacyVersions(user.getGivenName(), "revoked"));
            User updateUser = managementClient.users().update(userId, input).execute();
            if (updateUser == null) {
                return false;
            }
            saveHistory(user, null);
            LOGGER.info(String.format("User %s cancel privacy consent version %s for app version %s",
                    user.getId(), oneidPrivacyVersion, appVersion));
            return true;
        } catch (Exception e) {
            LOGGER.error("revoke privacy failed {}", e.getMessage());
            return false;
        }
    }

    /**
     * 根据社区获取包含特定隐私版本号的隐私设置.
     *
     * @param privacyVersions 隐私版本号
     * @return 返回包含特定隐私版本号的隐私设置
     */
    public String getPrivacyVersionWithCommunity(String privacyVersions) {
        if (privacyVersions == null || !privacyVersions.contains(":")) {
            return "";
        }
        try {
            HashMap<String, String> privacys = JSON.parseObject(privacyVersions, HashMap.class);
            String privacyAccept = privacys.get(community);
            if (privacyAccept == null) {
                return "";
            } else {
                return privacyAccept;
            }
        } catch (Exception e) {
            LOGGER.error("get privacy failed {}", e.getMessage());
            return "";
        }
    }
    private void saveHistory(User user, String newPrivacy) {
        String content;
        String type;
        String opt;
        // 根据传参判断保存的为签署还是撤销
        if (newPrivacy == null) {
            // 保存撤销记录
            content = getPrivacyVersionWithCommunity(user.getGivenName());
            type = "revokeTime";
            opt = "revoke";
        } else {
            // 保存签署记录
            content = newPrivacy;
            type = "acceptTime";
            opt = "accept";
        }
        if (StringUtils.isNotEmpty(content) && !"revoked".equals(content)) {
            Date date = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            sdf.setTimeZone(TimeZone.getTimeZone("GMT+8:00"));
            String nowTime = sdf.format(date);
            JSONObject json = new JSONObject();
            json.put("appVersion", appVersion);
            json.put("privacyVersion", content);
            json.put("opt", opt);
            json.put(type, nowTime);
            privacyHistoryService.savePrivacyHistory(json.toString(), user.getId());
        }
    }
    private boolean isValidCommunity(String communityIns) {
        for (String com : allowedCommunity) {
            if (communityIns.startsWith(com)) {
                return true;
            }
        }
        return false;
    }
    /**
     * 更新隐私版本号.
     *
     * @param previous 先前的版本号
     * @param version 新版本号
     * @return 返回更新后的隐私版本号
     */
    public String updatePrivacyVersions(String previous, String version) {
        if (!isValidCommunity(community)) {
            return "";
        }
        if (StringUtils.isBlank(previous)) {
            return createPrivacyVersions(version, false);
        }
        if (!previous.contains(":")) {
            if ("unused".equals(previous)) {
                return createPrivacyVersions(version, false);
            } else {
                HashMap<String, String> privacys = new HashMap<>();
                privacys.put("openeuler", previous);
                privacys.put(community, version);
                return JSON.toJSONString(privacys);
            }
        } else {
            try {
                HashMap<String, String> privacys = JSON.parseObject(previous, HashMap.class);
                privacys.put(community, version);
                return JSON.toJSONString(privacys);
            } catch (Exception e) {
                LOGGER.error("put privacy failed {}", e.getMessage());
                return createPrivacyVersions(version, false);
            }
        }
    }
    /**
     * 创建隐私版本号.
     *
     * @param version 版本号
     * @param needSlash 是否需要斜杠
     * @return 返回创建的隐私版本号
     */
    public String createPrivacyVersions(String version, Boolean needSlash) {
        if (!isValidCommunity(community)) {
            return "";
        }
        HashMap<String, String> privacys = new HashMap<>();
        privacys.put(community, version);
        if (needSlash) {
            return JSON.toJSONString(privacys).replaceAll("\"", "\\\\\"");
        } else {
            return JSON.toJSONString(privacys);
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

    /**
     * 使用访问令牌更新账户信息.
     *
     * @param token 访问令牌
     * @param account 新账户信息
     * @param type 类型
     * @return 如果成功更新账户信息则返回消息提示，否则返回 null
     */
    public String updateAccountInfo(String token, String account, String type) {
        try {
            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
            String dectoken = RSAUtil.privateDecrypt(token, privateKey);
            DecodedJWT decode = JWT.decode(dectoken);
            String userId = decode.getAudience().get(0);
            UpdateUserInput updateUserInput = new UpdateUserInput();
            switch (type.toLowerCase()) {
                case "email":
                    updateUserInput.withEmail(account);
                    break;
                case "phone":
                    updateUserInput.withPhone(account);
                    break;
                default:
                    return "false";
            }
            managementClient.users().update(userId, updateUserInput).execute();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return e.getMessage();
        }
        return "true";
    }
}
