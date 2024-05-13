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

/**
 * 数据访问对象类，用于处理 Oneid 数据库操作.
 */
@Repository
public class OneidDao {

    /**
     * 日志记录器，用于记录 OneidDao 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OneidDao.class);

    /**
     * 数据统计 API 主机地址.
     */
    @Value("${oneid.api.host}")
    private String apiHost;

    /**
     * Datastat图片 AK.
     */
    @Value("${datastat.img.ak}")
    private String datastatImgAk;

    /**
     * Datastat图片 SK.
     */
    @Value("${datastat.img.sk}")
    private String datastatImgSk;

    /**
     * Datastat图片终端点.
     */
    @Value("${datastat.img.endpoint}")
    private String datastatImgEndpoint;

    /**
     * Datastat图片存储桶名称.
     */
    @Value("${datastat.img.bucket.name}")
    private String datastatImgBucket;

    /**
     * 图片后缀名.
     */
    @Value("${datastat.img.photo.suffix}")
    private String photoSuffix;


    /**
     * Redis 数据访问对象.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * ObsClient 实例，用于操作对象存储服务.
     */
    private static ObsClient obsClient;

    /**
     * ObjectMapper 实例，用于JSON序列化和反序列化.
     */
    private static ObjectMapper objectMapper;


    /**
     * 初始化方法，在对象构造之后，初始化之前执行.
     */
    @PostConstruct
    public void init() {
        obsClient = new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint);
        objectMapper = new ObjectMapper();
    }

    /**
     * 获取管理令牌.
     *
     * @param poolId     连接池ID
     * @param poolSecret 连接池密钥
     * @return 管理令牌
     */
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
            LOGGER.error(e.getMessage());
        }
        return token;
    }

    /**
     * 创建用户.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param userJsonStr 用户JSON字符串
     * @return 包含用户信息的 JSON 对象
     */
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
            LOGGER.error(e.getMessage());
        }
        return user;
    }

    /**
     * 删除用户.
     *
     * @param poolId     连接池ID
     * @param poolSecret 连接池密钥
     * @param userId     用户ID
     * @return 操作是否成功的布尔值
     */
    public boolean deleteUser(String poolId, String poolSecret, String userId) {
        boolean res = false;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.delete(apiHost
                            + Constant.ONEID_USER_URD_PATH.replace("{account}", userId))
                    .header("Authorization", mToken)
                    .asJson();
            if (response.getStatus() == 200) {
                res = true;
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return res;
    }

    /**
     * 更新用户信息.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param userId      用户ID
     * @param userJsonStr 更新后的用户JSON字符串
     * @return 包含更新后用户信息的 JSON 对象
     */
    public JSONObject updateUser(String poolId, String poolSecret, String userId, String userJsonStr) {
        JSONObject user = null;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.put(apiHost
                            + Constant.ONEID_USER_URD_PATH.replace("{account}", userId))
                    .header("Content-Type", "application/json")
                    .header("Authorization", mToken)
                    .body(userJsonStr)
                    .asJson();

            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return user;
    }

    /**
     * 获取用户信息.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param account     用户账号
     * @param accountType 账号类型
     * @return 包含用户信息的 JSON 对象
     */
    public JSONObject getUser(String poolId, String poolSecret, String account, String accountType) {
        JSONObject user = null;
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.get(apiHost
                            + Constant.ONEID_USER_URD_PATH.replace("{account}", account))
                    .header("Authorization", mToken)
                    .queryString("userIdType", accountType)
                    .asJson();

            if (response.getStatus() == 200) {
                user = response.getBody().getObject().getJSONObject("data");
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return user;
    }

    /**
     * 检查密码并获取用户信息.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param account     用户账号
     * @param accountType 账号类型
     * @param password    用户密码
     * @return 包含用户信息的对象
     */
    public Object getUserWithPasswordCheck(String poolId, String poolSecret, String account,
                                           String accountType, String password) {
        try {
            String mToken = (String) redisDao.get(Constant.ONEID_TOKEN_KEY);
            if (StringUtils.isBlank(mToken) || "null".equals(mToken)) {
                mToken = getManagementToken(poolId, poolSecret);
            }

            HttpResponse<JsonNode> response = Unirest.get(apiHost
                            + Constant.ONEID_CHECK_PASSWORD_PATH.replace("{account}", account))
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
            LOGGER.error(e.getMessage());
            return e.getMessage();
        }
    }

    // 校验用户是否存在（用户名 or 邮箱 or 手机号）

    /**
     * 检查用户是否存在.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param account     用户账号
     * @param accountType 账号类型
     * @return 存在与否的布尔值
     */
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

    /**
     * 使用账号和验证码登录.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param account     用户账号
     * @param accountType 账号类型
     * @param code        验证码
     * @param appId       应用ID
     * @return 登录结果的对象
     */
    public Object loginByAccountCode(String poolId, String poolSecret, String account,
                                     String accountType, String code, String appId) {
        JSONObject user = getUser(poolId, poolSecret, account, accountType);
        if (user == null) {
            return "用户不存在";
        }
        user.accumulate("id_token", user.getString("id"));
        return user;
    }

    /**
     * 使用账号和密码登录.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param account     用户账号
     * @param accountType 账号类型
     * @param password    用户密码
     * @param appId       应用ID
     * @return 登录结果的对象
     */
    public Object loginByPassword(String poolId, String poolSecret, String account,
                                  String accountType, String password, String appId) {
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

    /**
     * 注销用户登录.
     *
     * @param idToken 用户身份令牌
     * @param appId   应用ID
     * @return 注销操作是否成功的布尔值
     */
    public boolean logout(String idToken, String appId) {
        return true;
    }

    /**
     * 更新用户头像.
     *
     * @param poolId     连接池ID
     * @param poolSecret 连接池密钥
     * @param userId     用户ID
     * @param file       头像文件
     * @return 包含更新后用户信息的 JSON 对象
     */
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

            if (!CommonUtil.isFileContentTypeValid(file)) {
                throw new Exception("File content type is invalid");
            }

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
            LOGGER.error(e.getMessage());
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    LOGGER.error(e.getMessage());
                }
            }
        }
        return user;
    }

    /**
     * 更新用户账号信息.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param userId      用户ID
     * @param oldAccount  旧账号
     * @param account     新账号
     * @param accountType 账号类型
     * @return 更新后的用户信息对象
     */
    public Object updateAccount(String poolId, String poolSecret, String userId,
                                String oldAccount, String account, String accountType) {
        JSONObject oldUser = getUser(poolId, poolSecret, userId, "id");
        if (oldUser == null) {
            return null;
        }
        // 老邮箱或者手机号校验
        HashMap<String, String> map = new HashMap<>();
        switch (accountType.toLowerCase()) {
            case "email":
                if (oldUser.isNull("email") || !oldUser.getString("email").equals(oldAccount)) {
                    return null;
                }
                if (StringUtils.isNotBlank(account) && isUserExists(poolId, poolSecret, account, accountType)) {
                    return "该邮箱已被其它账户绑定";
                }
                map.put("email", account);
                break;
            case "phone":
                if (oldUser.isNull("phone") || !oldUser.getString("phone").equals(oldAccount)) {
                    return null;
                }
                if (StringUtils.isNotBlank(account) && isUserExists(poolId, poolSecret, account, accountType)) {
                    return "该手机号已被其它账户绑定";
                }
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
            LOGGER.error(e.getMessage());
        }
        return user;
    }

    /**
     * 绑定用户账号.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param userId      用户ID
     * @param account     要绑定的账号
     * @param accountType 账号类型
     * @return 绑定操作结果的对象
     */
    public Object bindAccount(String poolId, String poolSecret, String userId, String account, String accountType) {
        JSONObject oldUser = getUser(poolId, poolSecret, userId, "id");
        if (oldUser == null) {
            return null;
        }
        // 老邮箱或者手机号校验
        HashMap<String, String> map = new HashMap<>();
        switch (accountType.toLowerCase()) {
            case "email":
                if (!oldUser.isNull("email") && StringUtils.isNotBlank(oldUser.getString("email"))) {
                    return "已经绑定了邮箱";
                }
                if (isUserExists(poolId, poolSecret, account, accountType)) {
                    return "该邮箱已被其它账户绑定";
                }
                map.put("email", account);
                break;
            case "phone":
                if (!oldUser.isNull("phone") && StringUtils.isNotBlank(oldUser.getString("phone"))) {
                    return "已经绑定了手机号";
                }
                if (isUserExists(poolId, poolSecret, account, accountType)) {
                    return "该手机号已被其它账户绑定";
                }
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
            LOGGER.error(e.getMessage());
        }
        return user;
    }

    /**
     * 修改用户密码.
     *
     * @param poolId      连接池ID
     * @param poolSecret  连接池密钥
     * @param account     用户账号
     * @param accountType 账号类型
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     * @return 修改密码操作结果的对象
     */
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
            if (user == null) {
                return "密码不合法或重复";
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return e.getMessage();
        }
        return user;
    }

}
