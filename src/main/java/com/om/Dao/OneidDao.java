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
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import com.obs.services.ObsClient;
import com.obs.services.model.PutObjectResult;
import com.om.Result.Constant;
import com.om.Utils.CommonUtil;

import org.apache.commons.lang3.StringUtils;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@Repository
public class OneidDao {

    private static final Logger logger =  LoggerFactory.getLogger(OneidDao.class);

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

    @Value("${datastat.img.photo.suffix}")
    String photoSuffix;

    @Autowired
    private RedisDao redisDao;

    public static ObsClient obsClient;

    private static ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        obsClient = new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint);
        objectMapper = new ObjectMapper();
    }

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

    public JSONObject createUser(String poolId, String poolSecret, String userJsonStr) {
        JSONObject user = null;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.post(apiHost + Constant.ONEID_USER_C_PATH)
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(userJsonStr)
                    .asJson();
            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return user;
    }

    public boolean deleteUser(String poolId, String poolSecret, String userId) {
        boolean res = false;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.delete(apiHost + Constant.ONEID_USER_URD_PATH.replace("{account}", userId))
                    .header("Authorization", mToken)
                    .asJson();
            if (response.getStatus() == 200) res = true;
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return res;
    }

    public JSONObject updateUser(String poolId, String poolSecret, String userId, String userJsonStr) {
        JSONObject user = null;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.put(apiHost + Constant.ONEID_USER_URD_PATH.replace("{account}", userId))
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(userJsonStr)
                    .asJson();

            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return user;
    }

    public JSONObject getUser(String poolId, String poolSecret, String account, String accountType) {
        JSONObject user = null;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.get(apiHost + Constant.ONEID_USER_URD_PATH.replace("{account}", account))
                    .header("Authorization", mToken)
                    .queryString("userIdType", accountType)
                    .asJson();

            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return user;
    }

    public Object getUserWithPasswordCheck(String poolId, String poolSecret, String account, 
                                    String accountType, String password) {
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.get(apiHost + Constant.ONEID_CHECK_PASSWORD_PATH.replace("{account}", account))
                    .header("Authorization", mToken)
                    .queryString("userIdType", accountType)
                    .queryString("password", password)
                    .asJson();

            if (response.getStatus() == 200) {
                return response.getBody().getObject().getJSONObject("data");
            } else {
                return response.getBody().getObject().getString("message");
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
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

    public Object loginByPassword(String poolId, String poolSecret, String account, String accountType, String password, String appId) {
        Object ret = getUserWithPasswordCheck(poolId, poolSecret, account, accountType, password);
        JSONObject user;
        if (ret instanceof JSONObject) {
            user = (JSONObject) ret;
            user.accumulate("id_token", user.getString("id"));
            return user;
        } else {
            return (String) ret;
        }
    }

    public boolean logout(String idToken, String appId) {
        return true;
    }

    public JSONObject updatePhoto(String poolId, String poolSecret, String userId, MultipartFile file) {
        JSONObject user = null;
        InputStream inputStream = null;
        try {
            inputStream = CommonUtil.rewriteImage(file);

            // 重命名文件
            String fileName = file.getOriginalFilename();
            for (String c : Constant.PHOTO_NOT_ALLOWED_CHARS.split(",")) {
                if (fileName.contains(c)) {
                    throw new Exception("Filename is invalid");
                }
            }
            String extension = fileName.substring(fileName.lastIndexOf("."));
            List<String> photoSuffixes = Arrays.asList(photoSuffix.split(";"));
            if (!photoSuffixes.contains(extension.toLowerCase())) {
                throw new Exception("Upload photo format is not acceptable");
            }

            if (!CommonUtil.isFileContentTypeValid(file)) throw new Exception("File content type is invalid");

            String objectName = String.format("%s%s", UUID.randomUUID().toString(), extension);

            //上传文件到OBS
            PutObjectResult putObjectResult = obsClient.putObject(datastatImgBucket, objectName, inputStream);
            String objectUrl = putObjectResult.getObjectUrl();

            // 修改用户头像
            HashMap<String, String> map = new HashMap<>();
            map.put("photo", objectUrl);
            String userJsonStr = objectMapper.writeValueAsString(map);
            user = updateUser(poolId, poolSecret, userId, userJsonStr);
        } catch (Exception e) {
            logger.error(e.getMessage());
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    logger.error(e.getMessage());
                }
            }
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
            logger.error(e.getMessage());
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
            logger.error(e.getMessage());
        }
        return user;
    }

    public Object modifyPassword(String poolId, String poolSecret, String account, 
                                 String accountType, String oldPassword, String newPassword) {
        Object ret = getUserWithPasswordCheck(poolId, poolSecret, account, accountType, oldPassword);
        JSONObject user;
        if (ret instanceof JSONObject) {
            user = (JSONObject) ret;
        } else {
            return (String) ret;
        }

        String id = user.getString("id");
        HashMap<String, String> map = new HashMap<>();
        map.put("password", newPassword);
        try {
            String userJsonString = objectMapper.writeValueAsString(map);
            user = updateUser(poolId, poolSecret, id, userJsonString);
            if (user == null) return "密码不合法或重复";
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
        return user;
    }

}
