/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Dao;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.obs.services.ObsClient;
import com.obs.services.model.PutObjectResult;
import com.om.Modules.UserIdentity;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.UUID;

@Repository
public class OneidDao {

    @Value("${oneid.api.host}")
    String apiHost;

    @Value("${datastat.img.ak}")
    String datastatImgAk;

    @Value("${datastat.img.sk}")
    String datastatImgSk;

    @Value("${datastat.img.endpoint}")
    String datastatImgEndpoint;

    @Value("${datastat.img.bucket.name}")
    String datastatImgBucket;

    public static ObsClient obsClient;

    private static ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        obsClient = new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint);
        objectMapper = new ObjectMapper();
    }

    private String getManagementToken(String poolId, String poolSecret) {
        String token = "";
        try {
            String body = String.format("{\"accessKeyId\": \"%s\",\"accessKeySecret\": \"%s\"}", poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.post(apiHost + "/auth/get-management-token")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            if (response.getStatus() == 200) {
                token = response.getBody().getObject().getString("data");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return token;
    }

    public JSONObject createUser(String poolId, String poolSecret, String userJsonStr) {
        JSONObject user = null;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.post(apiHost + "/composite-user")
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(userJsonStr)
                    .asJson();
            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public boolean deleteUser(String poolId, String poolSecret, String userId) {
        boolean res = false;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.delete(apiHost + "/composite-user/" + userId)
                    .header("Authorization", mToken)
                    .asJson();
            if (response.getStatus() == 200) res = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public JSONObject updateUser(String poolId, String poolSecret, String userId, String userJsonStr) {
        JSONObject user = null;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.put(apiHost + "/composite-user/" + userId)
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(userJsonStr)
                    .asJson();

            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public JSONObject getUser(String poolId, String poolSecret, String account, String accountType) {
        JSONObject user = null;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.get(apiHost + "/composite-user/" + account)
                    .header("Authorization", mToken)
                    .queryString("userIdType", accountType)
                    .asJson();

            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public JSONObject getUserByIdInIdp(String poolId, String poolSecret, Object userIdInIdp) {
        //TODO
        return null;
    }

    public JSONObject updateUserIdentity(String poolId, String poolSecret, String userId, String identityJsonStr) {
        JSONObject user = null;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.put(apiHost + "/external-user/" + userId)
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(identityJsonStr)
                    .asJson();
            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public JSONObject bindIdentityToUser(String poolId, String poolSecret, String userId, String identityJsonStr) {
        JSONObject user = null;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.post(apiHost + "/external-user/" + userId)
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(identityJsonStr)
                    .asJson();
            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
                user.accumulate("id_token", user.getString("id")); //TODO
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public boolean unbindIdentityByUser(String poolId, String poolSecret, String userId, String provider) {
        boolean res = false;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.delete(apiHost + "/external-user/" + userId)
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .queryString("provider", provider)
                    .asJson();
            if (response.getStatus() == 200) {
                res = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    // 校验用户是否存在（用户名 or 邮箱 or 手机号）
    public boolean isUserExists(String poolId, String poolSecret, String account, String accountType) {
        switch (accountType.toLowerCase()) {
            case "username":
            case "email":
            case "phone":
                JSONObject user = getUser(poolId, poolSecret, account, accountType);
                return user != null;
            default:
                return true;
        }
    }

    public Object loginByAccountCode(String poolId, String poolSecret, String account, String accountType, String code, String appId) {
        JSONObject user = getUser(poolId, poolSecret, account, accountType);
        if (user == null) return "用户不存在";
        user.accumulate("id_token", user.getString("id"));
        return user;
    }

    public boolean logout(String idToken, String appId) {
        return true;
    }

    public JSONObject updatePhoto(String poolId, String poolSecret, String userId, MultipartFile file) {
        JSONObject user = null;
        try {
            // 重命名文件
            String fileName = file.getOriginalFilename();
            String extension = fileName.substring(fileName.lastIndexOf("."));
            String objectName = String.format("%s%s", UUID.randomUUID().toString(), extension);

            //上传文件到OBS
            PutObjectResult putObjectResult = obsClient.putObject(datastatImgBucket, objectName, file.getInputStream());
            String objectUrl = putObjectResult.getObjectUrl();

            // 修改用户头像
            HashMap<String, String> map = new HashMap<>();
            map.put("photo", objectUrl);
            String userJsonStr = objectMapper.writeValueAsString(map);
            user = updateUser(poolId, poolSecret, userId, userJsonStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public Object updateAccount(String poolId, String poolSecret, String userId, String oldAccount, String account, String accountType) {
        JSONObject oldUser = getUser(poolId, poolSecret, userId, "id");
        if (oldUser == null)
            return null;
        // 老邮箱或者手机号校验
        HashMap<String, String> map = new HashMap<>();
        switch (accountType.toLowerCase()) {
            case "email":
                if (oldUser.isNull("email") || !oldUser.getString("email").equals(oldAccount))
                    return null;
                if (StringUtils.isNotBlank(account) && isUserExists(poolId, poolSecret, account, accountType))
                    return "该邮箱已被其它账户绑定";
                map.put("email", account);
                break;
            case "phone":
                if (oldUser.isNull("phone") || !oldUser.getString("phone").equals(oldAccount))
                    return null;
                if (StringUtils.isNotBlank(account) && isUserExists(poolId, poolSecret, account, accountType))
                    return "该手机号已被其它账户绑定";
                map.put("phone", account);
                break;
            default:
                return null;
        }
        // 修改邮箱或者手机号
        JSONObject user = null;
        try {
            String userJsonStr = objectMapper.writeValueAsString(map);
            user = updateUser(poolId, poolSecret, userId, userJsonStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }

    public Object bindAccount(String poolId, String poolSecret, String userId, String account, String accountType) {
        JSONObject oldUser = getUser(poolId, poolSecret, userId, "id");
        if (oldUser == null)
            return null;
        // 老邮箱或者手机号校验
        HashMap<String, String> map = new HashMap<>();
        switch (accountType.toLowerCase()) {
            case "email":
                if (!oldUser.isNull("email") && StringUtils.isNotBlank(oldUser.getString("email")))
                    return "已经绑定了邮箱";
                if (isUserExists(poolId, poolSecret, account, accountType))
                    return "该邮箱已被其它账户绑定";
                map.put("email", account);
                break;
            case "phone":
                if (!oldUser.isNull("phone") && StringUtils.isNotBlank(oldUser.getString("phone")))
                    return "已经绑定了手机号";
                if (isUserExists(poolId, poolSecret, account, accountType))
                    return "该手机号已被其它账户绑定";
                map.put("phone", account);
                break;
            default:
                return null;
        }
        // 修改邮箱或者手机号
        JSONObject user = null;
        try {
            String userJsonStr = objectMapper.writeValueAsString(map);
            user = updateUser(poolId, poolSecret, userId, userJsonStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }
}
