/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.Service;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.types.Application;
import cn.authing.core.types.User;

import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.GitDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;

import com.om.Utils.AuthingUtil;
import com.om.Utils.ClientIPUtil;
import com.om.Utils.LogUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class OneIdManageService {
    /**
     * 自动注入环境变量.
     */
    @Autowired
    private Environment env;

    /**
     * 自动注入 AuthingService 服务.
     */
    @Autowired
    private AuthingService authingService;

    /**
     * 自动注入 JwtTokenCreateService 服务.
     */
    @Autowired
    private JwtTokenCreateService jwtTokenCreateService;

    /**
     * 自动注入 AuthingUserDao 数据访问对象.
     */
    @Autowired
    private AuthingUserDao authingUserDao;

    /**
     * 自动注入 RedisDao 对象.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 自动注入 GitDao 对象.
     */
    @Autowired
    private GitDao gitDao;

    /**
     * 自动注入 ObjectMapper 对象.
     */
    @Autowired
    private ObjectMapper objectMapper;


    /**
     * 使用 @Autowired 注解注入authingUtil.
     */
    @Autowired
    private AuthingUtil authingUtil;

    /**
     * 从配置中获取企业Gitee提供者ID.
     */
    @Value("${enterprise.extIdpId.gitee}")
    private String giteeProviderId;

    /**
     * 从配置中获取社交GitHub提供者ID.
     */
    @Value("${social.extIdpId.github}")
    private String githubProviderId;

    /**
     * 静态日志记录器，用于记录 OneIdManageService 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OneIdManageService.class);

    /**
     * 参数默认值数组.
     */
    private static final String[] PARAMETER_DEFAULT_VALUE = new String[]{""};

    /**
     * 默认消息内容.
     */
    private static final String MSG_DEFAULT = "Internal Server Error";

    /**
     * 令牌正则表达式前缀.
     */
    private static final String TOKEN_REGEX = "token_info:";

    /**
     * 处理令牌申请请求.
     *
     * @param body 请求体参数映射
     * @return ResponseEntity 对象
     */
    public ResponseEntity tokenApply(Map<String, String> body) {
        try {
            String grantType = body.get("grant_type");
            if (StringUtils.isBlank(grantType)) {
                return result(HttpStatus.BAD_REQUEST,
                        "grant_type must be not blank", null);
            }

            /*
             * grantType=token,生成token和refresh_token
             * grantType=refresh_token,生成新的token和refresh_token
             */
            if (grantType.equalsIgnoreCase("token")) {
                String appId = body.get("app_id");
                String appSecret = body.get("app_secret");
                return tokenApply(appId, appSecret);
            } else if (grantType.equalsIgnoreCase("refresh_token")) {
                String token = body.get("token");
                String refreshToken = body.get("refresh_token");
                return refreshToken(token, refreshToken);
            } else {
                return result(HttpStatus.BAD_REQUEST,
                        "grant_type must be token or refresh_token", null);
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MSG_DEFAULT, null);
        }

    }

    /**
     * 发送验证码并返回 ResponseEntity.
     *
     * @param body      请求体参数映射
     * @param token     令牌
     * @param isSuccess 发送是否成功的标志
     * @return ResponseEntity 对象
     */
    public ResponseEntity sendCode(Map<String, String> body, String token, boolean isSuccess) {
        String account = body.get("account");
        String channel = body.get("channel");
        if (!Constant.AUTHING_CHANNELS.contains(channel.toUpperCase())) {
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }

        // 图片验证码二次校验
        if (!isSuccess) {
            return authingService.result(HttpStatus.BAD_REQUEST,
                    null, MessageCodeConfig.E0002.getMsgZh(), null);
        }

        // 限制1分钟只能发送一次
        String redisKey = account.toLowerCase() + "_sendcode";
        String codeOld = (String) redisDao.get(redisKey);
        if (codeOld != null) {
            return authingService.result(HttpStatus.BAD_REQUEST,
                    null, MessageCodeConfig.E0009.getMsgZh(), null);
        }

        String msg;
        String accountType = authingService.getAccountType(account);
        try {
            JsonNode jsonNode = getTokenInfo(token);
            String appId = jsonNode.get("app_id").asText();

            if (accountType.equals("email")) {
                msg = authingUserDao.sendEmailCodeV3(appId, account, channel);
            } else if (accountType.equals("phone")) {
                msg = authingUserDao.sendPhoneCodeV3(appId, account, channel);
            } else {
                return authingService.result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
        } catch (Exception e) {
            return authingService.result(HttpStatus.BAD_REQUEST, null, MessageCodeConfig.E0008.getMsgZh(), null);
        }

        if (!msg.equals("success")) {
            redisDao.set(redisKey, "code", Long.parseLong(Constant.DEFAULT_EXPIRE_SECOND));
            return authingService.result(HttpStatus.BAD_REQUEST, null, msg, null);
        } else {
            return result(HttpStatus.OK, "success", null);
        }
    }

    /**
     * 绑定账号的方法.
     *
     * @param servletRequest 请求入参
     * @param body  包含请求体信息的 Map 对象
     * @param token 包含在请求头中的令牌字符串
     * @return 返回 ResponseEntity 对象
     */
    public ResponseEntity bindAccount(HttpServletRequest servletRequest, Map<String, String> body, String token) {
        String account = body.get("account");
        String code = body.get("code");
        String userId = body.get("user_id");
        String accountType = body.get("account_type");
        String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType)) {
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }

        try {
            JsonNode jsonNode = getTokenInfo(token);
            User user = authingUserDao.getUser(userId);
            AuthenticationClient authentication =
                    authingUserDao.initUserAuthentication(jsonNode.get("app_id").asText(), user);
            String res = authingUserDao.bindAccount(authentication, account, code, accountType);
            if ("true".equals(res)) {
                LogUtil.createLogs(userId, "bind account", "user",
                        "The user bind account", userIp, "success");
            } else {
                LogUtil.createLogs(userId, "bind account", "user",
                        "The user bind account", userIp, "failed");
            }
            return authingService.message(res);
        } catch (Exception e) {
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
    }

    /**
     * 身份验证的方法.
     *
     * @param userCookie 用户 Cookie 值
     * @return 返回 ResponseEntity 对象
     */
    public ResponseEntity authenticate(String userCookie) {
        return authingService.authingUserPermission(userCookie);
    }

    /**
     * 获取用户信息的方法.
     *
     * @param username    用户名
     * @param userId      用户ID
     * @param giteeLogin  Gitee 登录名
     * @param githubLogin GitHub 登录名
     * @return 返回 ResponseEntity 对象
     */
    public ResponseEntity getUserInfo(String username, String userId, String giteeLogin, String githubLogin) {
        try {
            // only single param allowed
            List<String> params = Arrays.asList(username, userId, giteeLogin, githubLogin);
            int count = 0;
            for (String param : params) {
                if (StringUtils.isNotBlank(param)) {
                    count += 1;
                }
            }
            if (count != 1) {
                return authingService.result(
                        HttpStatus.BAD_REQUEST, MessageCodeConfig.E00064, null, null);
            }

            JSONObject userInfo = null;
            if (StringUtils.isNotBlank(userId)) {
                userInfo = authingUserDao.getUserById(userId);
            }
            if (StringUtils.isNotBlank(username)) {
                userInfo = authingUserDao.getUserByName(username);
            }
            if (StringUtils.isNotBlank(giteeLogin)) {
                String giteeId = gitDao.getGiteeUserIdByLogin(giteeLogin);
                if (StringUtils.isNotBlank(giteeId)) {
                    userInfo = authingUserDao.getUserV3(
                            giteeProviderId.concat(":").concat(giteeId), "identity");
                }
            }
            if (StringUtils.isNotBlank(githubLogin)) {
                String githubId = gitDao.getGithubUserIdByLogin(githubLogin);
                if (StringUtils.isNotBlank(githubId)) {
                    userInfo = authingUserDao.getUserV3(
                            githubProviderId.concat(":").concat(githubId), "identity");
                }
            }

            if (userInfo != null) {
                return authingService.result(HttpStatus.OK, null,
                        "success", authingUtil.parseAuthingUser(userInfo));
            } else {
                return authingService.result(HttpStatus.NOT_FOUND, MessageCodeConfig.E00034, null, null);
            }
        } catch (Exception e) {
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
    }

    /**
     * 撤销隐私设置的方法.
     *
     * @param userId 用户id
     * @param servletRequest 请求入参
     * @return 返回 ResponseEntity 对象
     */
    public ResponseEntity revokePrivacy(String userId, HttpServletRequest servletRequest) {
        try {
            String userIp = ClientIPUtil.getClientIpAddress(servletRequest);
            if (authingUserDao.revokePrivacy(userId)) {
                LogUtil.createLogs(userId, "update userInfo", "user",
                        "The user revoke privacy", userIp, "success");
                return authingService.result(HttpStatus.OK, MessageCodeConfig.S0001, null, null);
            }
            LogUtil.createLogs(userId, "update userInfo", "user",
                    "The user revoke privacy", userIp, "failed");
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
    }

    /**
     * APP是否存在，且密码是否正确.
     *
     * @param appId     appId
     * @param appSecret appSecret
     * @return app是否正确
     */
    private boolean isAppCorrect(String appId, String appSecret) {
        try {
            Application app = authingUserDao.getAppById(appId);
            return app != null && appSecret.equals(app.getSecret());
        } catch (Exception e) {
            LOGGER.error(String.format("Can't find app with id %s", appId));
            LOGGER.error(e.getMessage());
            return false;
        }
    }

    /**
     * 生成token和refresh_token.
     *
     * @param appId     appId
     * @param appSecret appSecret
     * @return token和refresh_token
     * @throws JsonProcessingException 创建失败
     */
    private Map<String, Object> createTokens(String appId, String appSecret)
            throws JsonProcessingException {
        // 过期时间
        long tokenExpire = Long.parseLong(
                env.getProperty("app.manager.token.expire", "1800"));
        long refTokenExpire = Long.parseLong(
                env.getProperty("app.manager.refresh.token.expire", "28800"));

        // jwt格式token和refresh_token
        String tokenJwt = jwtTokenCreateService.getAppManagerToken(
                appId, appSecret, tokenExpire);
        String refTokenJwt = jwtTokenCreateService.getAppManagerToken(
                appId, appSecret, refTokenExpire);

        // token和refresh_token的hash
        String token = DigestUtils.md5DigestAsHex(tokenJwt.getBytes(StandardCharsets.UTF_8));
        String refreshToken = DigestUtils.md5DigestAsHex(refTokenJwt.getBytes(StandardCharsets.UTF_8));

        // jwt格式token和refresh_token保存在服务端
        HashMap<String, Object> jwtTokenMap = new HashMap<>();
        jwtTokenMap.put("token", tokenJwt);
        jwtTokenMap.put("refresh_token", refTokenJwt);
        jwtTokenMap.put("app_id", appId);
        jwtTokenMap.put("app_secret", appSecret);
        String tokenStr = objectMapper.writeValueAsString(jwtTokenMap);
        redisDao.set(token, TOKEN_REGEX + tokenStr, refTokenExpire);

        // 返回token和refresh_token的hash
        HashMap<String, Object> tokenMap = new HashMap<>();
        tokenMap.put("token", token);
        tokenMap.put("refresh_token", refreshToken);
        return tokenMap;
    }

    /**
     * 申请app管理员的token和refresh_token.
     *
     * @param appId     appId
     * @param appSecret appSecret
     * @return token和refresh_token
     */
    private ResponseEntity tokenApply(String appId, String appSecret) {
        try {
            if (!isAppCorrect(appId, appSecret)) {
                return result(HttpStatus.BAD_REQUEST,
                        "app id or secret error", null);
            }

            Map<String, Object> tokens = createTokens(appId, appSecret);
            return result(HttpStatus.OK, "OK", tokens);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MSG_DEFAULT, null);
        }
    }

    /**
     * 使用旧token和refresh_token生成新的token和refresh_token.
     *
     * @param oldToken    旧token
     * @param oldRefToken 旧refresh_token
     * @return 新的token和refresh_token
     */
    private ResponseEntity refreshToken(String oldToken, String oldRefToken) {
        try {
            // 校验旧的token和refresh_token
            Object checkRes = checkTokens(oldToken, oldRefToken);
            if (!(checkRes instanceof JsonNode)) {
                return result(HttpStatus.BAD_REQUEST, (String) checkRes, null);
            }
            JsonNode tokenInfo = (JsonNode) checkRes;

            // 生成新的token和refresh_token，失效旧的
            String appId = tokenInfo.get("app_id").asText();
            String appSecret = tokenInfo.get("app_secret").asText();
            Map<String, Object> newTokens = createTokens(appId, appSecret);
            redisDao.remove(oldToken);

            return result(HttpStatus.OK, "OK", newTokens);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return result(HttpStatus.INTERNAL_SERVER_ERROR, MSG_DEFAULT, null);
        }
    }

    /**
     * 校验token和refresh_token.
     *
     * @param token        token
     * @param refreshToken refresh_token
     * @return 校验正确返回服务端存储的token信息
     */
    private Object checkTokens(String token, String refreshToken) {
        try {
            if (StringUtils.isBlank(token) || StringUtils.isBlank(refreshToken)) {
                return "must contain token and refresh_token";
            }

            // 校验token
            String tokenStr = (String) redisDao.get(token);
            if (StringUtils.isBlank(tokenStr)) {
                return "token error or expire";
            }

            // 校验refresh_token是否同缓存中一致
            String tokenInfo = tokenStr.replace(TOKEN_REGEX, "");
            JsonNode jsonNode = objectMapper.readTree(tokenInfo);
            String refTokenJwt = jsonNode.get("refresh_token").asText();
            if (!refreshToken.equals(DigestUtils.md5DigestAsHex(refTokenJwt.getBytes(StandardCharsets.UTF_8)))) {
                return "token error or expire";
            }

            // 校验refresh_token是否正确或过期
            String appSecret = jsonNode.get("app_secret").asText();
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(appSecret
                    + env.getProperty("authing.token.base.password"))).build();
            jwtVerifier.verify(refTokenJwt);

            return jsonNode;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return "token error or expire";
        }
    }

    private JsonNode getTokenInfo(String token) throws JsonProcessingException {
        String tokenStr = (String) redisDao.get(token);
        String tokenInfo = tokenStr.replace("token_info:", "");
        return objectMapper.readTree(tokenInfo);
    }

    private ResponseEntity result(HttpStatus status, String msg, Map<String, Object> claim) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("status", status.value());
        res.put("msg", msg);
        if (claim != null) {
            res.putAll(claim);
        }
        return new ResponseEntity<>(JSON.parseObject(
                HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), status);
    }
}
