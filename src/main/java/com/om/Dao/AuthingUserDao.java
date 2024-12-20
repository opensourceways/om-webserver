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

import cn.authing.core.auth.AuthenticationClient;

import cn.authing.core.types.Application;
import cn.authing.core.types.UpdateUserInput;
import cn.authing.core.types.User;
import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Modules.authing.AuthingAppSync;
import com.om.Service.PrivacyHistoryService;
import com.om.authing.AuthingRespConvert;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import com.obs.services.ObsClient;
import com.obs.services.model.PutObjectResult;
import com.om.Modules.MessageCodeConfig;
import com.om.Modules.ServerErrorException;
import com.om.Result.Constant;
import com.om.Utils.CommonUtil;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;

import jakarta.annotation.PostConstruct;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Date;
import java.util.TimeZone;
import java.util.Map;
import java.util.UUID;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 用于操作 Authing 用户数据的数据访问对象.
 */
@Repository
public class AuthingUserDao {
    /**
     * 日志记录器实例，用于记录 AuthingUserDao 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingUserDao.class);

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
     * DataStat 图像 AK.
     */
    @Value("${datastat.img.ak}")
    private String datastatImgAk;

    /**
     * DataStat 图像 SK.
     */
    @Value("${datastat.img.sk}")
    private String datastatImgSk;

    /**
     * DataStat 图像端点.
     */
    @Value("${datastat.img.endpoint}")
    private String datastatImgEndpoint;

    /**
     * DataStat 图像存储桶名称.
     */
    @Value("${datastat.img.bucket.name}")
    private String datastatImgBucket;


    /**
     * GitHub 社交登录的外部身份提供者 ID.
     */
    @Value("${social.extIdpId.github}")
    private String socialExtIdpIdGithub;

    /**
     * GitHub 社交登录的标识符.
     */
    @Value("${social.identifier.github}")
    private String socialIdentifierGithub;

    /**
     * GitHub 社交登录的授权 URL.
     */
    @Value("${social.authorizationUrl.github}")
    private String socialAuthUrlGithub;

    /**
     * 微信 社交登录的外部身份提供者 ID.
     */
    @Value("${social.extIdpId.wechat: }")
    private String socialExtIdpIdWechat;

    /**
     * 微信 社交登录的标识符.
     */
    @Value("${social.identifier.wechat: }")
    private String socialIdentifierWechat;

    /**
     * 微信 社交登录的授权 URL.
     */
    @Value("${social.authorizationUrl.wechat: }")
    private String socialAuthUrlWechat;

    /**
     * Gitee 企业登录的外部身份提供者 ID.
     */
    @Value("${enterprise.extIdpId.gitee}")
    private String enterExtIdpIdGitee;

    /**
     * Gitee 企业登录的标识符.
     */
    @Value("${enterprise.identifier.gitee}")
    private String enterIdentifieGitee;

    /**
     * Gitee 企业登录的授权 URL.
     */
    @Value("${enterprise.authorizationUrl.gitee}")
    private String enterAuthUrlGitee;

    /**
     * OpenAtom 企业登录的外部身份提供者 ID.
     */
    @Value("${enterprise.extIdpId.openatom}")
    private String enterExtIdpIdOpenatom;

    /**
     * OpenAtom 企业登录的标识符.
     */
    @Value("${enterprise.identifier.openatom}")
    private String enterIdentifieOpenatom;


    /**
     * OpenAtom 企业登录的授权 URL.
     */
    @Value("${enterprise.authorizationUrl.openatom}")
    private String enterAuthUrlOpenatom;

    /**
     * GitCode 企业登录的外部身份提供者 ID.
     */
    @Value("${enterprise.extIdpId.gitcode: }")
    private String enterExtIdpIdGitCode;

    /**
     * GitCode 企业登录的标识符.
     */
    @Value("${enterprise.identifier.gitcode: }")
    private String enterIdentifiedGitCode;

    /**
     * GitCode 企业登录的授权 URL.
     */
    @Value("${enterprise.authorizationUrl.gitcode: }")
    private String enterAuthUrlGitCode;

    /**
     * Authing 的 RSA 私钥.
     */
    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;

    /**
     * 预留的用户名.
     */
    @Value("${username.reserved}")
    private String usernameReserved;

    /**
     * DataStat 默认照片路径.
     */
    @Value("${datastat.img.default.photo}")
    private String defaultPhoto;

    /**
     * 照片后缀.
     */
    @Value("${datastat.img.photo.suffix}")
    private String photoSuffix;

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
     * AIGC 隐私版本号.
     */
    @Value("${aigc.privacy.version}")
    private String aigcPrivacyVersion;

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
     * 临时外部身份提供者 IDs.
     */
    @Value("${temp.extIdpIds}")
    private String extIdpIds;

    /**
     * 临时标识符列表.
     */
    @Value("${temp.identifiers}")
    private String identifiers;

    /**
     * 临时用户列表.
     */
    @Value("${temp.users}")
    private String users;

    /**
     * OBS 客户端实例.
     */
    private static ObsClient obsClient;

    /**
     * 预留用户名列表.
     */
    private static List<String> reservedUsernames;

    /**
     * 照片后缀列表.
     */
    private List<String> photoSuffixes;

    /**
     * 允许的社区列表.
     */
    private List<String> allowedCommunity;

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
     * Authing 应用程序同步对象.
     */
    @Autowired
    private AuthingAppSync authingAppSync;

    /**
     * 历史隐私记录保存类.
     */
    @Autowired
    private PrivacyHistoryService privacyHistoryService;

    /**
     * Authing的管理面接口.
     */
    @Autowired
    private AuthingManagerDao authingManagerDao;

    /**
     * OBS客户端实例赋值.
     *
     * @param obsClient OBS客户端实例
     */
    public static void setInitObsClient(ObsClient obsClient) {
        AuthingUserDao.obsClient = obsClient;
    }

    /**
     * 预留用户名列表赋值.
     *
     * @param nameList 预留用户名列表
     */
    public static void setInitReservedUsernames(List<String> nameList) {
        AuthingUserDao.reservedUsernames = nameList;
    }

    /**
     * 在类实例化后立即执行的初始化方法.
     */
    @PostConstruct
    public void init() {
        setInitObsClient(new ObsClient(datastatImgAk, datastatImgSk, datastatImgEndpoint));
        setInitReservedUsernames(getUsernameReserved());
        photoSuffixes = Arrays.asList(photoSuffix.split(";"));
        Unirest.config().reset();
        Unirest.config().socketTimeout(Constant.SOCKET_TIMEOUT).connectTimeout(Constant.CONNECT_TIMEOUT);
        allowedCommunity = Arrays.asList(Constant.OPEN_EULER, Constant.MIND_SPORE, Constant.MODEL_FOUNDRY,
                Constant.OPEN_UBMC);
    }

    /**
     * 发送手机验证码.
     *
     * @param appId   应用程序 ID
     * @param account 账号信息
     * @param channel 渠道信息
     * @return 返回发送结果信息
     */
    public String sendPhoneCodeV3(String appId, String account, String channel) {
        String msg = "success";
        try {
            String phoneCountryCode = getPhoneCountryCode(account);
            account = getPurePhone(account);
            String body = String.format("{\"phoneNumber\": \"%s\",\"channel\": \"%s\",\"phoneCountryCode\": \"%s\"}",
                    account, channel.toUpperCase(), phoneCountryCode);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + "/send-sms")
                    .header("x-authing-app-id", appId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) {
                msg = AuthingRespConvert.convertMsg(resObj, null);
            }

            return msg;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return MessageCodeConfig.E0008.getMsgZh();
        }
    }

    /**
     * 发送电子邮件验证码.
     *
     * @param appId   应用程序 ID
     * @param account 账号信息
     * @param channel 渠道信息
     * @return 返回发送结果信息
     */
    public String sendEmailCodeV3(String appId, String account, String channel) {
        String msg = "success";
        try {
            String body = String.format("{\"email\": \"%s\",\"channel\": \"%s\"}", account, channel.toUpperCase());
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + "/send-email")
                    .header("x-authing-app-id", appId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();

            JSONObject resObj = response.getBody().getObject();
            int statusCode = resObj.getInt("statusCode");
            if (statusCode != 200) {
                msg = AuthingRespConvert.convertMsg(resObj, null);
            }

            return msg;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return MessageCodeConfig.E0008.getMsgZh();
        }
    }

    // 邮箱验证码注册

    /**
     * 使用电子邮件验证码注册用户.
     *
     * @param appId    应用程序 ID
     * @param email    电子邮件地址
     * @param code     邮件验证码
     * @param username 用户名
     * @param clientIp 用户IP
     * @return 返回注册结果信息
     */
    public String registerByEmailCode(String appId, String email, String code, String username, String clientIp) {
        String body = String.format("{\"connection\": \"PASSCODE\","
                        + "\"passCodePayload\": {\"email\": \"%s\",\"passCode\": \"%s\"},"
                        + "\"options\": {\"clientIp\": \"%s\"},"
                        + "\"profile\":{\"username\":\"%s\", \"givenName\":\"%s\"}}",
                email, code, clientIp, username, createPrivacyVersions(oneidPrivacyVersion, true));
        return register(appId, body);
    }

    // 手机验证码注册

    /**
     * 使用手机验证码注册用户.
     *
     * @param appId    应用程序 ID
     * @param phone    手机号码
     * @param code     手机验证码
     * @param username 用户名
     * @param clientIp 用户IP
     * @return 返回注册结果信息
     */
    public String registerByPhoneCode(String appId, String phone, String code, String username, String clientIp) {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"connection\": \"PASSCODE\","
                        + "\"passCodePayload\": {\"phone\": \"%s\",\"passCode\": \"%s\",\"phoneCountryCode\": \"%s\"},"
                        + "\"options\": {\"clientIp\": \"%s\"},"
                        + "\"profile\":{\"username\":\"%s\", \"givenName\":\"%s\"}}",
                phone, code, phoneCountryCode, clientIp, username, createPrivacyVersions(oneidPrivacyVersion, true));
        return register(appId, body);
    }

    // 邮箱验密码注册

    /**
     * 使用电子邮件和密码注册用户.
     *
     * @param appId    应用程序 ID
     * @param email    电子邮件地址
     * @param password 密码
     * @param username 用户名
     * @param code     验证码
     * @param clientIp 用户IP
     * @return 返回注册结果信息
     */
    public String registerByEmailPwd(String appId, String email, String password, String username, String code,
                                     String clientIp) {
        String body = String.format("{\"connection\": \"PASSWORD\","
                        + "\"passwordPayload\": {\"username\": \"%s\",\"password\": \"%s\"},"
                        + "\"profile\":{\"email\":\"%s\", \"givenName\":\"%s\"},"
                        + "\"options\":{\"passwordEncryptType\":\"rsa\","
                        + " \"emailPassCodeForInformationCompletion\":\"%s\",\"clientIp\": \"%s\"}}",
                username, password, email, createPrivacyVersions(oneidPrivacyVersion, true), code, clientIp);
        return register(appId, body);
    }

    /**
     * 使用手机号码和密码注册用户.
     *
     * @param appId    应用程序 ID
     * @param phone    手机号码
     * @param password 密码
     * @param username 用户名
     * @param code     验证码
     * @param clientIp 用户IP
     * @return 返回注册结果信息
     */
    public String registerByPhonePwd(String appId, String phone, String password, String username, String code,
                                     String clientIp) {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"connection\": \"PASSWORD\","
                        + "\"passwordPayload\": {\"username\": \"%s\",\"password\": \"%s\"},"
                        + "\"profile\":{\"phone\":\"%s\", \"phoneCountryCode\":\"%s\", \"givenName\":\"%s\"},"
                        + "\"options\":{\"passwordEncryptType\":\"rsa\", "
                        + "\"phonePassCodeForInformationCompletion\":\"%s\",\"clientIp\": \"%s\"}}",
                username, password, phone, phoneCountryCode,
                createPrivacyVersions(oneidPrivacyVersion, true), code, clientIp);
        return register(appId, body);
    }

    /**
     * 检查用户是否存在.
     *
     * @param appId       应用程序 ID
     * @param account     账号信息
     * @param accountType 账号类型
     * @return 如果用户存在，则返回 true；否则返回 false
     * @throws ServerErrorException 服务器错误异常
     */
    public boolean isUserExists(String appId, String account, String accountType) throws ServerErrorException {
        try {
            AuthenticationClient authentication = authingAppSync.getAppClientById(appId);
            return switch (accountType.toLowerCase()) {
                case "username" -> authentication.isUserExists(account, null, null, null).execute();
                case "email" -> authentication.isUserExists(null, account, null, null).execute();
                case "phone" -> authentication.isUserExists(null, null, account, null).execute();
                default -> true;
            };
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            throw new ServerErrorException();
        }
    }

    /**
     * 使用电子邮件验证码登录.
     *
     * @param app   应用程序对象
     * @param email 电子邮件地址
     * @param code  邮件验证码
     * @return 返回登录结果对象
     * @param clientIp 用户IP
     * @throws ServerErrorException 服务器错误异常
     */
    public Object loginByEmailCode(Application app, String email, String code, String clientIp)
            throws ServerErrorException {
        String body = String.format("{\"connection\": \"PASSCODE\","
            + "\"passCodePayload\": {\"email\": \"%s\",\"passCode\": \"%s\"},"
            + "\"options\": {\"autoRegister\": true,\"clientIp\": \"%s\"},"
            + "\"client_id\":\"%s\",\"client_secret\":\"%s\"}", email, code, clientIp, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    /**
     * 使用手机验证码登录.
     *
     * @param app   应用程序对象
     * @param phone 手机号码
     * @param code  手机验证码
     * @param clientIp 用户IP
     * @return 返回登录结果对象
     * @throws ServerErrorException 服务器错误异常
     */
    public Object loginByPhoneCode(Application app, String phone, String code, String clientIp)
            throws ServerErrorException {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"connection\": \"PASSCODE\","
                        + "\"passCodePayload\": {\"phone\": \"%s\",\"passCode\": \"%s\",\"phoneCountryCode\": \"%s\"},"
                        + "\"options\": {\"autoRegister\": true,\"clientIp\": \"%s\"},"
                        + "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                phone, code, phoneCountryCode, clientIp, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    /**
     * 使用电子邮件和密码进行登录.
     *
     * @param app      应用程序对象
     * @param email    电子邮件地址
     * @param password 密码
     * @param clientIp 用户IP
     * @return 返回登录结果对象
     * @throws ServerErrorException 服务器错误异常
     */
    public Object loginByEmailPwd(Application app, String email, String password, String clientIp)
            throws ServerErrorException {
        if (!isUserExists(app.getId(), email, "email")) {
            return MessageCodeConfig.E00052.getMsgZh();
        }

        String body = String.format("{\"connection\": \"PASSWORD\","
                        + "\"passwordPayload\": {\"email\": \"%s\",\"password\": \"%s\"},"
                        + "\"options\": {\"passwordEncryptType\": \"rsa\",\"clientIp\": \"%s\"},"
                        + "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                email, password, clientIp, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    /**
     * 使用手机号码和密码进行登录.
     *
     * @param app      应用程序对象
     * @param phone    手机号码
     * @param password 密码
     * @param clientIp 用户IP
     * @return 返回登录结果对象
     * @throws ServerErrorException 服务器错误异常
     */
    public Object loginByPhonePwd(Application app, String phone, String password, String clientIp)
            throws ServerErrorException {
        phone = getPurePhone(phone);

        if (!isUserExists(app.getId(), phone, "phone")) {
            return MessageCodeConfig.E00052.getMsgZh();
        }

        String body = String.format("{\"connection\": \"PASSWORD\","
                        + "\"passwordPayload\": {\"phone\": \"%s\",\"password\": \"%s\"},"
                        + "\"options\": {\"passwordEncryptType\": \"rsa\",\"clientIp\": \"%s\"},"
                        + "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                phone, password, clientIp, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    /**
     * 使用用户名和密码进行登录.
     *
     * @param app      应用程序对象
     * @param username 用户名
     * @param password 密码
     * @param clientIp 用户IP
     * @return 返回登录结果对象
     * @throws ServerErrorException 服务器错误异常
     */
    public Object loginByUsernamePwd(Application app, String username, String password, String clientIp)
            throws ServerErrorException {
        if (!isUserExists(app.getId(), username, "username")) {
            return MessageCodeConfig.E00052.getMsgZh();
        }

        String body = String.format("{\"connection\": \"PASSWORD\","
                        + "\"passwordPayload\": {\"username\": \"%s\",\"password\": \"%s\"},"
                        + "\"options\": {\"passwordEncryptType\": \"rsa\",\"clientIp\": \"%s\"},"
                        + "\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                username, password, clientIp, app.getId(), app.getSecret());
        return login(app.getId(), body);
    }

    /**
     * 获取应用程序注销重定向 URI 列表.
     *
     * @param appId 应用程序 ID
     * @return 返回指定应用程序的注销重定向 URI 列表
     */
    public List<String> getAppLogoutRedirectUris(String appId) {
        List<String> redirectUris = new ArrayList<>();
        Application execute = getAppById(appId);
        if (execute != null) {
            redirectUris = execute.getLogoutRedirectUris();
        }
        return redirectUris;
    }

    /**
     * 通过应用程序 ID 获取应用程序对象.
     *
     * @param appId 应用程序 ID
     * @return 返回指定应用程序 ID 对应的应用程序对象，如果不存在则返回 null
     */
    public Application getAppById(String appId) {
        Application app = authingAppSync.getAppById(appId);
        if (app == null) {
            LOGGER.error(String.format("Can't find app with id %s", appId));
        }
        return app;
    }

    /**
     * 通过访问令牌获取用户信息的映射.
     *
     * @param appId       应用程序 ID
     * @param code        授权码
     * @param redirectUrl 重定向 URL
     * @return 返回包含用户信息的映射，如果无法获取则返回空映射
     */
    public Map getUserInfoByAccessToken(String appId, String code, String redirectUrl) {
        try {
            AuthenticationClient authentication = authingAppSync.getAppClientById(appId);

            // code换access_token
            authentication.setRedirectUri(redirectUrl);
            Map res = (Map) authentication.getAccessTokenByCode(code).execute();
            String accessToken = res.get("access_token").toString();

            // access_token换user
            Map user = (Map) authentication.getUserInfoByAccessToken(accessToken).execute();
            user.put("id_token", res.get("id_token").toString());
            return user;
        } catch (Exception ex) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", ex.getMessage());
            return null;
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
            String token = getManagementToken();
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
     * 通过用户名获取用户信息.
     *
     * @param username 用户名
     * @return 返回包含用户信息的 JSONObject 对象，如果未找到用户则返回 null
     */
    public JSONObject getUserByName(String username) {
        try {
            User user = authingManagerDao.getUserByName(username);
            if (user == null) {
                return null;
            }
            return getUserById(user.getId());
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

    /**
     * 通过令牌获取应用用户信息.
     *
     * @param token 用户令牌
     * @return 返回包含应用用户信息的对象数组
     * @throws InvalidKeySpecException  无效密钥规范异常
     * @throws NoSuchAlgorithmException 无此算法异常
     * @throws InvalidKeyException      无效密钥异常
     * @throws NoSuchPaddingException   无此填充异常
     */
    public Object[] getAppUserInfo(String token) throws InvalidKeySpecException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(rsaAuthingPrivateKey);
        token = RSAUtil.privateDecrypt(token, privateKey);
        DecodedJWT decode = JWT.decode(token);
        String userId = decode.getAudience().get(0);
        String appId = decode.getClaim("client_id").asString();
        User user = authingManagerDao.getUser(userId);
        return new Object[]{appId, user};
    }

    /**
     * 根据用户 ID 获取用户详细信息.
     *
     * @param userId 用户 ID
     * @return 返回包含用户信息的 JSONObject 对象，如果未找到用户则返回 null
     */
    public JSONObject getUserById(String userId) {
        try {
            String token = getManagementToken();
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
            String token = getManagementToken();
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
     * 获取公钥字符串.
     *
     * @return 返回包含公钥的字符串
     */
    public String getPublicKey() {
        String msg = MessageCodeConfig.E00048.getMsgEn();
        try {
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV3 + "/system").asJson();
            if (response.getStatus() == 200) {
                JSONObject resObj = response.getBody().getObject();
                resObj.remove("sm2");
                resObj.remove("version");
                resObj.remove("publicIps");
                msg = resObj.toString();
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return msg;
    }

    /**
     * 使用访问令牌更新用户密码.
     *
     * @param token 访问令牌
     * @param oldPwd 旧密码
     * @param newPwd 新密码
     * @return 如果成功更新密码则返回消息提示，否则返回 null
     */
    public String updatePassword(String token, String oldPwd, String newPwd) {
        String msg = MessageCodeConfig.E00053.getMsgZh();
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];

            String body = String.format("{\"newPassword\": \"%s\","
                    + "\"oldPassword\": \"%s\","
                    + "\"passwordEncryptType\": \"rsa\"}", newPwd, oldPwd);
            HttpResponse<JsonNode> response = authPost("/update-password", appId, user.getToken(), body);
            JSONObject resObj = response.getBody().getObject();
            msg = resObj.getInt("statusCode") != 200 ? AuthingRespConvert.convertMsg(resObj, msg) : Constant.SUCCESS;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return msg;
    }

    /**
     * 重置密码并验证用户邮箱.
     *
     * @param appId 应用程序 ID
     * @param email 邮箱地址
     * @param code 验证码
     * @return 返回包含重置密码和验证邮箱操作结果的对象
     */
    public Object resetPwdVerifyEmail(String appId, String email, String code) {
        String body = String.format("{\"verifyMethod\": \"EMAIL_PASSCODE\","
                + "\"emailPassCodePayload\": "
                + "{\"email\": \"%s\",\"passCode\": \"%s\"}}", email, code);
        return resetPwdVerify(appId, body);
    }

    /**
     * 重置密码并验证用户手机号码.
     *
     * @param appId 应用程序 ID
     * @param phone 手机号码
     * @param code 验证码
     * @return 返回包含重置密码和验证手机号码操作结果的对象
     */
    public Object resetPwdVerifyPhone(String appId, String phone, String code) {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"verifyMethod\": \"PHONE_PASSCODE\","
                        + "\"phonePassCodePayload\": "
                        + "{\"phoneNumber\": \"%s\",\"passCode\": \"%s\",\"phoneCountryCode\": \"%s\"}}",
                phone, code, phoneCountryCode);
        return resetPwdVerify(appId, body);
    }

    /**
     * 重置密码.
     *
     * @param pwdResetToken 密码重置令牌
     * @param newPwd 新密码
     * @return 返回重置密码操作的结果消息
     */
    public String resetPwd(String pwdResetToken, String newPwd) {
        String msg = MessageCodeConfig.E00053.getMsgZh();
        try {
            String body = String.format("{\"passwordResetToken\": \"%s\","
                    + "\"password\": \"%s\","
                    + "\"passwordEncryptType\": \"rsa\"}", pwdResetToken, newPwd);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV3 + "/reset-password")
                    .header("Content-Type", "application/json").body(body).asJson();
            JSONObject resObj = response.getBody().getObject();
            msg = resObj.getInt("statusCode") != 200 ? AuthingRespConvert.convertMsg(resObj, msg) : Constant.SUCCESS;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return msg;
    }

    /**
     * 使用访问令牌更新账户信息.
     *
     * @param token 访问令牌
     * @param oldAccount 旧账户信息
     * @param oldCode 旧代码
     * @param account 新账户信息
     * @param code 新代码
     * @param type 类型
     * @return 如果成功更新账户信息则返回消息提示，否则返回 null
     */
    public String updateAccount(String token, String oldAccount, String oldCode,
                                String account, String code, String type) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User us = (User) appUserInfo[1];
            AuthenticationClient authentication = initUserAuthentication(appId, us);
            switch (type.toLowerCase()) {
                case "email":
                    authentication.updateEmail(account, code, oldAccount, oldCode).execute();
                    break;
                case "phone":
                    updatePhoneWithAuthingCode(oldAccount, oldCode, account, code, appId, us.getToken());
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return e.getMessage();
        }
        return "true";
    }

    /**
     * 使用访问令牌解绑账户.
     *
     * @param token 访问令牌
     * @param account 要解绑的账户信息
     * @param type 账户类型
     * @return 如果成功解绑账户则返回消息提示，否则返回 null
     */
    public String unbindAccount(String token, String account, String type) {
        String resFail = "unbind fail";
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User us = (User) appUserInfo[1];
            AuthenticationClient authentication = initUserAuthentication(appId, us);

            if (StringUtils.isBlank(us.getEmail())) {
                return "请先绑定邮箱";
            }
            switch (type.toLowerCase()) {
                // 目前不允许解绑邮箱
                case "phone":
                    String phone = us.getPhone();
                    if (!account.equals(phone)) {
                        return resFail;
                    }
                    authentication.unbindPhone().execute();
                    break;
                default:
                    return resFail;
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return e.getMessage();
        }
        return "unbind success";
    }

    /**
     * 初始化用户认证客户端.
     *
     * @param appId 应用程序 ID
     * @param user 用户对象
     * @return 返回初始化后的用户认证客户端
     */
    public AuthenticationClient initUserAuthentication(String appId, User user) {
        // 此处需要指定用户名，不能使用缓存的client，否则有并发问题
        AuthenticationClient appClient = null;
        Application app = getAppById(appId);
        if (app != null) {
            String appHost = "https://" + app.getIdentifier() + ".authing.cn";
            appClient = new AuthenticationClient(appId, appHost);
            appClient.setSecret(app.getSecret());
        } else {
            return appClient;
        }
        appClient.setCurrentUser(user);
        return appClient;
    }

    /**
     * 绑定账户到认证客户端.
     *
     * @param authentication 认证客户端
     * @param account 要绑定的账户信息
     * @param code 验证码
     * @param type 账户类型
     * @return 如果成功绑定账户则返回消息提示，否则返回 null
     */
    public String bindAccount(AuthenticationClient authentication, String account, String code, String type) {
        try {
            switch (type.toLowerCase()) {
                case "email":
                    authentication.bindEmail(account, code).execute();
                    break;
                case "phone":
                    authentication.bindPhone(account, code).execute();
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            return e.getMessage();
        }
        return "true";
    }

    /**
     * 使用令牌绑定账户.
     *
     * @param token 访问令牌
     * @param account 要绑定的账户信息
     * @param code 验证码
     * @param type 账户类型
     * @return 如果成功绑定账户则返回消息提示，否则返回 null
     */
    public String bindAccount(String token, String account, String code, String type) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];
            AuthenticationClient authentication = initUserAuthentication(appId, user);
            switch (type.toLowerCase()) {
                case "email":
                    String emailInDb = user.getEmail();
                    // situation: email is auto-generated
                    if (StringUtils.isNotBlank(emailInDb) && emailInDb.endsWith(Constant.AUTO_GEN_EMAIL_SUFFIX)) {
                        bindEmailWithSelfDistributedCode(authentication, user.getId(), account, code);
                    } else {
                        authentication.bindEmail(account, code).execute();
                    }
                    break;
                case "phone":
                    bindPhoneWithAuthingCode(account, code, appId, user.getToken());
                    break;
                default:
                    return "false";
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return e.getMessage();
        }
        return "true";
    }

    private void bindEmailWithSelfDistributedCode(
            AuthenticationClient authentication, String userId, String account, String code) throws Exception {
        String redisKey = account.toLowerCase() + "_CodeBindEmail";
        String codeTemp = (String) redisDao.get(redisKey);
        if (codeTemp == null) {
            throw new Exception("验证码无效或已过期");
        }
        if (!codeTemp.equals(code)) {
            throw new Exception("验证码不正确");
        }

        // check if email is bind to other account
        if (authentication.isUserExists(null, account, null, null).execute()) {
            throw new Exception("该邮箱已被其它账户绑定");
        }

        String res = authingManagerDao.updateEmailById(userId, account);

        if (res.equals(account)) {
            redisDao.remove(redisKey);
        } else {
            throw new Exception("服务异常");
        }
    }

    private void bindPhoneWithAuthingCode(String phone, String code, String appId, String token) throws Exception {
        String phoneCountryCode = getPhoneCountryCode(phone);
        phone = getPurePhone(phone);

        String body = String.format("{\"phoneNumber\": \"%s\","
                        + "\"passCode\": \"%s\","
                        + "\"phoneCountryCode\": \"%s\"}",
                phone, code, phoneCountryCode);

        HttpResponse<JsonNode> response = authPost("/bind-phone", appId, token, body);
        JSONObject resObj = response.getBody().getObject();
        if (resObj.getInt("statusCode") != 200) {
            throw new Exception(resObj.getString("message"));
        }
    }

    private void updatePhoneWithAuthingCode(String oldPhone, String oldCode, String newPhone, String newCode,
                                            String appId, String token) throws Exception {
        String oldPhoneCountryCode = getPhoneCountryCode(oldPhone);
        oldPhone = getPurePhone(oldPhone);
        String newPhoneCountryCode = getPhoneCountryCode(newPhone);
        newPhone = getPurePhone(newPhone);

        String body = String.format("{\"verifyMethod\": \"PHONE_PASSCODE\","
                        + "\"phonePassCodePayload\": {"
                        + "\"oldPhoneNumber\": \"%s\",\"oldPhonePassCode\": \"%s\",\"oldPhoneCountryCode\": \"%s\","
                        + "\"newPhoneNumber\": \"%s\",\"newPhonePassCode\": \"%s\",\"newPhoneCountryCode\": \"%s\"}}",
                oldPhone, oldCode, oldPhoneCountryCode, newPhone, newCode, newPhoneCountryCode);

        HttpResponse<JsonNode> response = authPost("/verify-update-phone-request", appId, token, body);
        JSONObject resObj = response.getBody().getObject();
        if (resObj.getInt("statusCode") != 200) {
            throw new Exception(resObj.getString("message"));
        }

        Object reqObj = resObj.get("data");
        String reqToken;
        if (reqObj instanceof JSONObject) {
            JSONObject req = (JSONObject) reqObj;
            reqToken = req.getString("updatePhoneToken");
        } else {
            throw new Exception("服务异常");
        }
        applyUpdatePhoneToken(appId, token, reqToken);
    }

    private void applyUpdatePhoneToken(String appId, String userToken, String updatePhoneToken) throws Exception {
        String body = String.format("{\"updatePhoneToken\": \"%s\"}", updatePhoneToken);

        HttpResponse<JsonNode> response = authPost("/update-phone", appId, userToken, body);
        JSONObject resObj = response.getBody().getObject();
        if (resObj.getInt("statusCode") != 200) {
            throw new Exception(resObj.getString("message"));
        }
    }

    /**
     * 获取连接列表信息.
     *
     * @param token 访问令牌
     * @return 返回包含连接信息的列表，每个连接作为一个 Map 对象存储
     */
    public List<Map<String, String>> linkConnList(String token) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];

            String userToken = user.getToken();
            List<Map<String, String>> list = new ArrayList<>();

            HashMap<String, String> mapGithub = new HashMap<>();
            String authGithub = String.format(socialAuthUrlGithub, socialIdentifierGithub, appId, userToken);
            mapGithub.put("name", "social_github");
            mapGithub.put("authorizationUrl", authGithub);

            HashMap<String, String> mapGitee = new HashMap<>();
            String authGitee = String.format(enterAuthUrlGitee, appId, enterIdentifieGitee, userToken);
            mapGitee.put("name", "enterprise_gitee");
            mapGitee.put("authorizationUrl", authGitee);

            HashMap<String, String> mapOpenatom = new HashMap<>();
            String authOpenatom = String.format(enterAuthUrlOpenatom, appId, enterIdentifieOpenatom, userToken);
            mapOpenatom.put("name", "enterprise_openatom");
            mapOpenatom.put("authorizationUrl", authOpenatom);

            list.add(mapGithub);
            list.add(mapGitee);
            list.add(mapOpenatom);
            if (StringUtils.isNotBlank(socialAuthUrlWechat)) {
                HashMap<String, String> mapWechat = new HashMap<>();
                String authWechat = String.format(socialAuthUrlWechat, socialIdentifierWechat, appId, userToken);
                mapWechat.put("name", "social_wechat");
                mapWechat.put("authorizationUrl", authWechat);
                list.add(mapWechat);
            }
            if (StringUtils.isNotBlank(enterAuthUrlGitCode)) {
                Map<String, String> mapGitCode = new HashMap<>();
                String authGitCode = String.format(enterAuthUrlGitCode, appId, enterIdentifiedGitCode, userToken);
                mapGitCode.put("name", "enterprise_gitcode");
                mapGitCode.put("authorizationUrl", authGitCode);
                list.add(mapGitCode);
            }
            return list;
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException" + e.getMessage());
            return null;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }
    }

    /**
     * 使用两个令牌绑定账户.
     *
     * @param token 第一个访问令牌
     * @param secondToken 第二个访问令牌
     * @return 返回绑定账户操作的结果消息
     */
    public String linkAccount(String token, String secondToken) {
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User us = (User) appUserInfo[1];
            AuthenticationClient authentication = initUserAuthentication(appId, us);

            authentication.linkAccount(token, secondToken).execute();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return e.getMessage();
        }
        return "true";
    }

    /**
     * 使用令牌解除与特定平台的账户绑定.
     *
     * @param token 访问令牌
     * @param platform 要解除链接的平台
     * @param community 社区
     * @return 返回解除账户链接操作的结果消息
     */
    public String unLinkAccount(String token, String platform, String community) {
        String msg = "解绑三方账号失败";
        String identifier;
        String extIdpId;
        try {
            switch (platform.toLowerCase()) {
                case "github":
                    identifier = socialIdentifierGithub;
                    extIdpId = socialExtIdpIdGithub;
                    break;
                case "gitee":
                    identifier = enterIdentifieGitee;
                    extIdpId = enterExtIdpIdGitee;
                    break;
                case "openatom":
                    identifier = enterIdentifieOpenatom;
                    extIdpId = enterExtIdpIdOpenatom;
                    break;
                case "gitcode":
                    identifier = enterIdentifiedGitCode;
                    extIdpId = enterExtIdpIdGitCode;
                    break;
                case "wechat":
                    identifier = socialIdentifierWechat;
                    extIdpId = socialExtIdpIdWechat;
                    break;
                default:
                    return msg;
            }

            Object[] appUserInfo = getAppUserInfo(token);
            User us = (User) appUserInfo[1];

            if (Constant.OPEN_MIND.equals(community)) {
                // openmind账号，邮箱不是必选项
                if (StringUtils.isBlank(us.getPhone())) {
                    return "Please bind the phone number first";
                }
            } else if (StringUtils.isBlank(us.getEmail())) {
                return "请先绑定邮箱";
            }
            // -- temporary (解决gitee多身份源解绑问题)
            List<String> userIds = Stream.of(users.split(";")).toList();
            if (platform.toLowerCase().equals("gitee") && userIds.contains(us.getId())) {
                if (unLinkAccountTemp(us, identifiers, extIdpIds)) {
                    return "success";
                } else {
                    return msg;
                }
            }

            String body = String.format("{\"identifier\":\"%s\",\"extIdpId\":\"%s\"}", identifier, extIdpId);
            HttpResponse<JsonNode> response = Unirest.post(authingApiHostV2 + "/users/identity/unlinkByUser")
                    .header("Authorization", us.getToken())
                    .header("x-authing-userpool-id", userPoolId)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .asJson();
            if (response.getBody().getObject().getInt("code") == 200) {
                msg = "success";
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return msg;
    }

    /**
     * 临时解除用户与外部标识提供者之间的关联.
     *
     * @param us 用户对象
     * @param identifiers 标识符
     * @param extIdpIds 外部标识提供者 ID
     * @return 如果成功解除关联则返回 true，否则返回 false
     */
    public boolean unLinkAccountTemp(User us, String identifiers, String extIdpIds) {
        boolean flag = false;

        String[] split = identifiers.split(";");
        String[] split1 = extIdpIds.split(";");
        for (int i = 0; i < split.length; i++) {
            try {
                String body = String.format("{\"identifier\":\"%s\",\"extIdpId\":\"%s\"}", split[i], split1[i]);
                HttpResponse<JsonNode> response = Unirest.post(authingApiHostV2 + "/users/identity/unlinkByUser")
                        .header("Authorization", us.getToken())
                        .header("x-authing-userpool-id", userPoolId)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .asJson();
                if (response.getBody().getObject().getInt("code") == 200) {
                    flag = true;
                }
            } catch (Exception e) {
                LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            }
        }
        return flag;
    }

    /**
     * 使用访问令牌更新用户基本信息.
     *
     * @param token 访问令牌
     * @param map 包含要更新的用户基本信息的映射
     * @return 更新用户基本信息的结果消息
     * @throws ServerErrorException 如果更新过程中出现服务器错误
     */
    public String updateUserBaseInfo(String token, Map<String, Object> map) throws ServerErrorException {
        String msg = "success";
        try {
            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];

            UpdateUserInput updateUserInput = new UpdateUserInput();
            String community = (String) map.getOrDefault("community", null);

            for (Map.Entry<String, Object> entry : map.entrySet()) {
                String item = entry.getKey();
                String inputValue = entry.getValue() == null ? "" : entry.getValue().toString();
                switch (item.toLowerCase()) {
                    case "nickname":
                        updateUserInput.withNickname(inputValue);
                        break;
                    case "company":
                        updateUserInput.withCompany(inputValue);
                        break;
                    case "username":
                        msg = checkUsername(appId, inputValue, community);
                        if (!msg.equals("success")) {
                            return msg;
                        }
                        if (Objects.nonNull(user)) {
                            String userName = user.getUsername();
                            if (Objects.nonNull(userName)
                                    && StringUtils.isNotBlank(userName)
                                    && !userName.startsWith("oauth2_")) {
                                return "用户名唯一，不可修改";
                            }
                        }
                        updateUserInput.withUsername(inputValue);
                        break;
                    case "aigcprivacyaccepted":
                        if (aigcPrivacyVersion.equals(inputValue)) {
                            updateUserInput.withFormatted(aigcPrivacyVersion);
                        }
                        if ("revoked".equals(inputValue)) {
                            updateUserInput.withFormatted("revoked");
                        }
                        break;
                    case "oneidprivacyaccepted":
                        if (oneidPrivacyVersion.equals(inputValue)) {
                            updateUserInput.withGivenName(updatePrivacyVersions(user.getGivenName(),
                                    oneidPrivacyVersion));
                            LOGGER.info(String.format("User %s accept privacy version %s for app version %s",
                                    user.getId(), inputValue, appVersion));
                            // 签署新的隐私协议时，先保存撤销的到历史隐私记录
                            saveHistory(user, null);
                            // 再保存新的隐私协议以及签署时间。
                            saveHistory(user, inputValue);
                        }
                        if ("revoked".equals(inputValue)) {
                            // 取消签署的隐私协议时，也保存撤销到历史隐私记录。
                            saveHistory(user, null);
                            updateUserInput.withGivenName(updatePrivacyVersions(user.getGivenName(), "revoked"));
                            LOGGER.info(String.format("User %s cancel privacy consent version %s for app version %s",
                                    user.getId(), inputValue, appVersion));
                        }
                        break;
                    default:
                        break;
                }
            }
            authingManagerDao.updateUserInfo(user.getId(), updateUserInput);
            return msg;
        } catch (ServerErrorException e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            throw e;
        } catch (Exception ex) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", ex.getMessage());
            return MessageCodeConfig.E0007.getMsgZh();
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

    /**
     * 使用访问令牌更新用户照片.
     *
     * @param token 访问令牌
     * @param file 包含新用户照片的文件
     * @return 如果成功更新用户照片则返回 true，否则返回 false
     */
    public boolean updatePhoto(String token, MultipartFile file) {
        InputStream inputStream = null;
        try {
            inputStream = CommonUtil.rewriteImage(file);

            Object[] appUserInfo = getAppUserInfo(token);
            String appId = appUserInfo[0].toString();
            User user = (User) appUserInfo[1];
            AuthenticationClient authentication = initUserAuthentication(appId, user);

            String photo = user.getPhoto();

            // 重命名文件
            String fileName = file.getOriginalFilename();
            if (Objects.isNull(fileName)) {
                throw new Exception("Filename is invalid");
            }
            for (String c : Constant.PHOTO_NOT_ALLOWED_CHARS.split(",")) {
                if (fileName.contains(c)) {
                    throw new Exception("Filename is invalid");
                }
            }
            String extension = fileName.substring(fileName.lastIndexOf("."));
            if (!photoSuffixes.contains(extension.toLowerCase())) {
                return false;
            }

            if (!CommonUtil.isFileContentTypeValid(file)) {
                throw new Exception("File content type is invalid");
            }

            String objectName = String.format("%s%s", UUID.randomUUID().toString(), extension);

            //上传文件到OBS
            PutObjectResult putObjectResult = obsClient.putObject(datastatImgBucket, objectName, inputStream);
            String objectUrl = putObjectResult.getObjectUrl();

            // 修改用户头像
            authentication.updateProfile(new UpdateUserInput().withPhoto(objectUrl)).execute();

            // 删除旧的头像
            deleteObsObjectByUrl(photo);
            return true;
        } catch (Exception ex) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", ex.getMessage());
            return false;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    LOGGER.error(e.getMessage());
                }
            }
        }
    }

    /**
     * 根据对象 URL 删除 OBS 对象.
     *
     * @param objectUrl 对象的 URL
     */
    public void deleteObsObjectByUrl(String objectUrl) {
        try {
            if (StringUtils.isBlank(objectUrl)) {
                return;
            }

            int beginIndex = objectUrl.lastIndexOf("/");
            beginIndex = beginIndex == -1 ? 0 : beginIndex + 1;
            String objName = objectUrl.substring(beginIndex);
            if (obsClient.doesObjectExist(datastatImgBucket, objName) && !objName.equals(defaultPhoto)) {
                obsClient.deleteObject(datastatImgBucket, objName);
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
    }

    private String getManagementToken() {
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
     * 检查用户名是否合规.
     *
     * @param appId 应用程序 ID
     * @param userName 用户名
     * @param community 社区名
     * @return 如果用户名可用则返回消息提示，否则返回错误信息
     * @throws ServerErrorException 如果在检查过程中出现服务器错误
     */
    public String checkUsername(String appId, String userName, String community) throws ServerErrorException {
        String msg = "success";
        if (StringUtils.isBlank(userName)) {
            msg = "用户名不能为空";
            return msg;
        }
        if (Constant.OPEN_MIND.equals(community)) {
            if (userName.length() < Constant.OPEN_MIND_USERNAME_MIN
                    || userName.length() > Constant.OPEN_MIND_USERNAME_MAX
                    || !userName.matches(Constant.OPEN_MIND_USERNAME_REGEX)) {
                msg = "[openMind] username invalid";
                return msg;
            }
        } else {
            if (!userName.matches(Constant.USERNAMEREGEX)) {
                msg = "请输入3到20个字符。只能由字母、数字或者下划线(_)组成。必须以字母开头，不能以下划线(_)结尾";
                return msg;
            }
        }
        if (reservedUsernames.contains(userName) || isUserExists(appId, userName, "username")) {
            msg = "用户名已存在";
            return msg;
        }

        return msg;
    }

    /**
     * 获取用户可访问的应用程序列表.
     *
     * @param userId 用户ID
     * @return 包含用户可访问的应用程序名称的列表
     */
    public List<String> userAccessibleApps(String userId) {
        ArrayList<String> appIds = new ArrayList<>();
        try {
            String token = authingManagerDao.getUser(userId).getToken();
            HttpResponse<JsonNode> response = Unirest.get(authingApiHostV3 + "/get-my-accessible-apps")
                    .header("Authorization", token)
                    .header("x-authing-userpool-id", userPoolId)
                    .asJson();
            if (response.getStatus() == 200) {
                JSONArray data = response.getBody().getObject().getJSONArray("data");
                for (Object item : data) {
                    if (item instanceof JSONObject) {
                        JSONObject app = (JSONObject) item;
                        appIds.add(app.getString("appId"));
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return appIds;
    }

    private List<String> getUsernameReserved() {
        if (StringUtils.isBlank(usernameReserved)) {
            return null;
        }
        return Arrays.stream(usernameReserved.split(",")).map(String::trim).collect(Collectors.toList());
    }

    private String register(String appId, String body) {
        String msg = Constant.SUCCESS;
        try {
            HttpResponse<JsonNode> response = authPost("/signup", appId, body);
            JSONObject resObj = response.getBody().getObject();
            if (resObj.getInt("statusCode") != 200) {
                msg = AuthingRespConvert.convertMsg(resObj, MessageCodeConfig.E00024.getMsgZh());
            }
            return msg;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return MessageCodeConfig.E00024.getMsgZh();
        }
    }

    private Object login(String appId, String body) {
        Object msg = MessageCodeConfig.E00027.getMsgZh();
        return authPostResData("/signin", appId, body, msg);
    }

    private Object resetPwdVerify(String appId, String body) {
        Object msg = MessageCodeConfig.E00012.getMsgZh();
        return authPostResData("/verify-reset-password-request", appId, body, msg);
    }

    private Object authPostResData(String uriPath, String appId, String body, Object defaultMsg) {
        Object msg = defaultMsg;
        try {
            HttpResponse<JsonNode> response = authPost(uriPath, appId, body);
            JSONObject resObj = response.getBody().getObject();
            if (resObj.getInt("statusCode") == 403 && resObj.has("apiCode") && resObj.getInt("apiCode") == 2006) {
                // 防止直接提示密码错误
                msg = MessageCodeConfig.E00052.getMsgZh();
            } else {
                msg = (resObj.getInt("statusCode") == 200)
                        ? resObj.get("data")
                        : AuthingRespConvert.convertMsg(resObj, (String) defaultMsg);
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return msg;
    }

    private HttpResponse<JsonNode> authPost(String uriPath, String appId, String body)
            throws UnirestException {
        return Unirest.post(authingApiHostV3 + uriPath)
                .header("x-authing-app-id", appId)
                .header("Content-Type", "application/json")
                .body(body)
                .asJson();
    }

    private HttpResponse<JsonNode> authPost(String uriPath, String appId, String token,
                                            String body) throws UnirestException {
        return Unirest.post(authingApiHostV3 + uriPath)
                .header("Authorization", token)
                .header("x-authing-app-id", appId)
                .header("Content-Type", "application/json")
                .body(body)
                .asJson();
    }

    /**
     * 获取电话号码对应的国家/地区代码.
     *
     * @param phone 电话号码
     * @return 返回电话号码对应的国家/地区代码
     */
    public String getPhoneCountryCode(String phone) {
        String phoneCountryCode = "+86";
        String[] countryCodes = env.getProperty("sms.international.countrys.code", "").split(",");
        for (String countryCode : countryCodes) {
            if (phone.startsWith(countryCode)) {
                phoneCountryCode = countryCode;
            }
        }
        return phoneCountryCode;
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
                LOGGER.error(e.getMessage());
                return createPrivacyVersions(version, false);
            }
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
            LOGGER.error(e.getMessage());
            return "";
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
}
