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

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

@Repository
public class OneidDao {

    @Value("${oneid.api.host}")
    String apiHost;

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
            HttpResponse<JsonNode> response = Unirest.post(apiHost + "/users")
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + mToken)
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

    public String deleteUser(String poolId, String poolSecret) {
        String res = "fail";
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            String body = String.format("{\"accessKeyId\": \"%s\",\"accessKeySecret\": \"%s\"}", poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.delete(apiHost + "/admin/user/delete-users-batch")
                    .header("Authorization", "Bearer " + mToken)
                    .body("")
                    .asJson();
            if (response.getStatus() == 200) {
                res = "success";
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public JSONObject updateUser(String poolId, String poolSecret) {
        try {
            String mToken = getManagementToken(poolId, poolSecret);

            String body = String.format("{\"accessKeyId\": \"%s\",\"accessKeySecret\": \"%s\"}", poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.put(apiHost + "/admin/user/update-user")
                    .header("Authorization", "Bearer " + mToken)
                    .body("")
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
        } catch (Exception e) {

        }
        return null;
    }

    public JSONObject getUser(String poolId, String poolSecret, String account, String accountType) {
        JSONObject user = null;
        try {
            String mToken = getManagementToken(poolId, poolSecret);
            HttpResponse<JsonNode> response = Unirest.get(apiHost + "/users/" + account)
                    .header("Authorization", "Bearer " + mToken)
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
}
