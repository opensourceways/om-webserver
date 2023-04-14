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

package com.om.Service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.OneidDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.JwtTokenCreateService;
import com.om.Service.inter.UserCenterServiceInter;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Service("opengauss")
public class OpenGaussService implements UserCenterServiceInter {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    OneidDao oneidDao;

    @Autowired
    JavaMailSender mailSender;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    private static HashMap<String, Boolean> domain2secure;

    private static CodeUtil codeUtil;

    private static Map<String, MessageCodeConfig> error2code;

    private static Result result;

    private static Map<String, String> appId2Secret;

    private static ObjectMapper objectMapper;

    private static List<String> channels;

    private static String poolId;

    private static String poolSecret;

    @PostConstruct
    public void init() {
        codeUtil = new CodeUtil();
        error2code = authingUserDao.getErrorCode();
        appId2Secret = getApps();
        result = new Result();
        channels = getSendCodeChannel();
        objectMapper = new ObjectMapper();
        poolId = env.getProperty("opengauss.pool.key");
        poolSecret = env.getProperty("opengauss.pool.secret");
        domain2secure = HttpClientUtils.getConfigCookieInfo(Objects.requireNonNull(env.getProperty("cookie.token.domains")), Objects.requireNonNull(env.getProperty("cookie.token.secures")));
    }

    @Override
    public ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        try {
            String community = servletRequest.getParameter("community");
            String appId = servletRequest.getParameter("client_id");
            String userName = servletRequest.getParameter("username");
            String account = servletRequest.getParameter("account");
            String code = servletRequest.getParameter("code");
            String company = servletRequest.getParameter("company");

            // 限制一分钟内失败次数
            String registerErrorCountKey = account + "registerCount";
            Object v = redisDao.get(registerErrorCountKey);
            int registerErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
            if (registerErrorCount >= Integer.parseInt(env.getProperty("login.error.count", "6")))
                return result(HttpStatus.BAD_REQUEST, null, "请求过于频繁", null);

            HashMap<String, Object> userInfo = new HashMap<>();
            // 公司名校验
            if (company == null || !company.matches(Constant.COMPANYNAMEREGEX))
                return result(HttpStatus.BAD_REQUEST, null, "请输入2到100个字符。公司只能由字母、数字、汉字、括号或者点(.)、逗号(,)、&组成。必须以字母、数字或者汉字开头，不能以括号、逗号(,)和&结尾", null);
            userInfo.put("company", company);

            // app校验
            if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
                return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

            // 用户名校验
            if (StringUtils.isBlank(userName))
                return result(HttpStatus.BAD_REQUEST, null, "用户名不能为空", null);
            if (!userName.matches(Constant.USERNAMEREGEX))
                return result(HttpStatus.BAD_REQUEST, null, "请输入3到20个字符。只能由字母、数字或者下划线(_)组成。必须以字母开头，不能以下划线(_)结尾", null);
            if (oneidDao.isUserExists(poolId, poolSecret, userName, "username"))
                return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);
            userInfo.put("username", userName);

            // 手机号或者邮箱校验
            String accountType = getAccountType(account);
            if (accountType.equals("请输入正确的手机号或者邮箱")) {
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
            }
            if (oneidDao.isUserExists(poolId, poolSecret, account, accountType)) {
                return result(HttpStatus.BAD_REQUEST, null, "该账号已注册", null);
            }
            userInfo.put(accountType, account);

            // 验证码校验
            String redisKey = account + "_sendCode_" + community + "_register";
            String codeTemp = (String) redisDao.get(redisKey);
            String codeCheck = checkCode(code, codeTemp);
            if (!codeCheck.equals("success")) {
                long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
                registerErrorCount += 1;
                redisDao.set(registerErrorCountKey, String.valueOf(registerErrorCount), codeExpire);
                return result(HttpStatus.BAD_REQUEST, null, codeCheck, null);
            }

            // 用户注册
            String userJsonStr = objectMapper.writeValueAsString(userInfo);
            JSONObject user = oneidDao.createUser(poolId, poolSecret, userJsonStr);
            if (user == null) {
                return result(HttpStatus.BAD_REQUEST, null, "注册失败", null);
            } else {
                // 注册成功，验证码失效，解除注册失败次数限制
                redisDao.remove(registerErrorCountKey);
                redisDao.updateValue(redisKey, codeTemp + "_used", 0);
                return result(HttpStatus.OK, null, "success", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null);
        }
    }

    @Override
    public ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess) {
        try {
            String community = servletRequest.getParameter("community");
            String account = servletRequest.getParameter("account");
            String channel = servletRequest.getParameter("channel");

            // 验证码二次校验
            if (!isSuccess)
                return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);

            // channel校验
            if (StringUtils.isBlank(channel) || !channels.contains(channel.toLowerCase())) {
                return result(HttpStatus.BAD_REQUEST, null, "channel error", null);
            }

            // 限制1分钟只能发送一次
            String redisKeyTemp = account + "_sendCode_" + community;
            String redisKey = channel.toLowerCase().equals("channel_register") ? redisKeyTemp + "_register" : redisKeyTemp;
            String codeOld = (String) redisDao.get(redisKey);
            if (codeOld != null) {
                return result(HttpStatus.BAD_REQUEST, null, "一分钟之内已发送过验证码", null);
            }

            // 发送验证码
            String accountType = getAccountType(account);
            String[] strings = codeUtil.sendCode(accountType, account, mailSender, env, community.toLowerCase());
            if (StringUtils.isBlank(strings[0]) || !strings[2].equals("send code success"))
                return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);

            redisDao.set(redisKey, strings[0], Long.parseLong(strings[1]));
            return result(HttpStatus.OK, null, strings[2], null);
        } catch (Exception e) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);
        }
    }

    @Override
    public ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String userName = servletRequest.getParameter("username");
        String account = servletRequest.getParameter("account");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        if (StringUtils.isNotBlank(userName)) {
            boolean username = oneidDao.isUserExists(poolId, poolSecret, userName, "username");
            if (username) return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);
        } else if (StringUtils.isNotBlank(account)) {
            String accountType = checkPhoneAndEmail(poolId, poolSecret, account);
            if (!accountType.equals("email") && !accountType.equals("phone"))
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        return result(HttpStatus.OK, null, "success", null);
    }

    @Override
    public ResponseEntity login(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        // 限制一分钟登录失败次数
        String loginErrorCountKey = account + "loginCount";
        Object v = redisDao.get(loginErrorCountKey);
        int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
        if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.count", "6")))
            return result(HttpStatus.BAD_REQUEST, null, "失败次数过多，请稍后重试", null);

        // 验证码校验
        String redisKey = account + "_sendCode_" + community;
        String codeTemp = (String) redisDao.get(redisKey);
        String codeCheck = checkCode(code, codeTemp);
        if (!codeCheck.equals("success")) {
            long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
            loginErrorCount += 1;
            redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
            return result(HttpStatus.BAD_REQUEST, null, codeCheck, null);
        }

        // 登录
        String accountType = getAccountType(account);
        Object msg;
        if (accountType.equals("email") || accountType.equals("phone")) {
            // todo 待调用oneid-server
            msg = oneidDao.loginByAccountCode(poolId, poolSecret, account, accountType, code, appId);
        } else {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }

        String idToken;
        JSONObject user;
        if (msg instanceof JSONObject) {
            user = (JSONObject) msg;
            idToken = user.getString("id_token");
        } else {
            long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
            loginErrorCount += 1;
            redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
            return result(HttpStatus.BAD_REQUEST, null, (String) msg, null);
        }

        //登录成功解除登录失败次数限制
        redisDao.remove(loginErrorCountKey);

        // 生成token
        String[] tokens = jwtTokenCreateService.authingUserToken(appId, user.getString("id"),
                user.getString("username"), "", "", idToken);
        String token = tokens[0];
        String verifyToken = tokens[1];

        // 写cookie
        String cookieTokenName = env.getProperty("cookie.token.name");
        String maxAgeTemp = env.getProperty("authing.cookie.max.age");
        int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : Integer.parseInt(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds")));
        HttpClientUtils.setCookie(servletRequest, servletResponse, cookieTokenName, token, true, maxAge, "/", domain2secure);

        // 返回结果
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", verifyToken);
        userData.put("photo", jsonObjStringValue(user, "photo"));
        userData.put("username", jsonObjStringValue(user, "username"));
        userData.put("email_exist", !user.isNull("email"));

        // 登录成功，验证码失效
        redisDao.updateValue(redisKey, codeTemp + "_used", 0);
        return result(HttpStatus.OK, null, "success", userData);
    }

    @Override
    public ResponseEntity personalCenterUserInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        JSONObject userObj = null;
        try {
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            userObj = oneidDao.getUser(poolId, poolSecret, userId, "id");
        } catch (Exception e) {
            e.printStackTrace();
        }

        HashMap<String, Object> userData = new HashMap<>();
        userData.put("username", jsonObjStringValue(userObj, "username"));
        userData.put("email", jsonObjStringValue(userObj, "email"));
        userData.put("phone", jsonObjStringValue(userObj, "phone"));
        userData.put("signedUp", jsonObjStringValue(userObj, "createAt"));
        userData.put("nickname", jsonObjStringValue(userObj, "nickname"));
        userData.put("company", jsonObjStringValue(userObj, "company"));
        userData.put("photo", jsonObjStringValue(userObj, "photo"));

        // 返回结果
        return result(HttpStatus.OK, null, "success", userData);
    }

    @Override
    public ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String community = servletRequest.getParameter("community");
            String appId = servletRequest.getParameter("client_id");

            // app校验
            if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
                return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

            String headerToken = servletRequest.getHeader("token");
            String idTokenKey = "idToken_" + headerToken;
            String idToken = (String) redisDao.get(idTokenKey);

            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();

            // todo 待调用oneid-server
            boolean logout = oneidDao.logout(idToken, appId);
            if (!logout) return result(HttpStatus.BAD_REQUEST, null, "退出登录失败", null);

            // 退出登录，该token失效
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 退出登录，删除cookie，删除idToken
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(servletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(idTokenKey);

            return result(HttpStatus.OK, null, "success", null);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, null, "unauthorized", null);
        }
    }

    @Override
    public ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String community = servletRequest.getParameter("community");
            String appId = servletRequest.getParameter("client_id");

            // app校验
            if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
                return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

            // 获取用户
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            JSONObject user = oneidDao.getUser(poolId, poolSecret, userId, "id");

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", jsonObjStringValue(user, "photo"));
            userData.put("username", jsonObjStringValue(user, "username"));
            return result(HttpStatus.OK, null, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, null, "unauthorized", null);
        }
    }

    @Override
    public ResponseEntity deleteUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();

            JSONObject user = oneidDao.getUser(poolId, poolSecret, userId, "id");
            String photo = jsonObjStringValue(user, "photo");

            //用户注销
            boolean res = oneidDao.deleteUser(poolId, poolSecret, userId);
            if (res) {
                return deleteUserAfter(servletRequest, servletResponse, token, userId, issuedAt, photo);
            } else {
                return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
            }
        } catch (Exception e) {
            return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        }
    }

    @Override
    public ResponseEntity updateUserBaseInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token, Map<String, Object> map) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        try {
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);

            // 只允许修改 nickname 和 company
            map.entrySet().removeIf(entry -> !(entry.getKey().equals("nickname") || entry.getKey().equals("company")));
            String nickname = (String) map.getOrDefault("nickname", null);
            if (nickname != null && !nickname.equals("") && !nickname.matches(Constant.NICKNAMEREGEX)) {
                String msg = "请输入3到20个字符。昵称只能由字母、数字、汉字或者下划线(_)组成。" +
                        "必须以字母或者汉字开头，不能以下划线(_)结尾";
                return result(HttpStatus.BAD_REQUEST, null, msg, null);
            }

            String company = (String) map.getOrDefault("company", null);
            if (company != null && !company.matches(Constant.COMPANYNAMEREGEX)) {
                String msg = "请输入2到100个字符。公司只能由字母、数字、汉字、括号或者点(.)、逗号(,)、&组成。" +
                        "必须以字母、数字或者汉字开头，不能以括号、逗号(,)和&结尾";
                return result(HttpStatus.BAD_REQUEST, null, msg, null);
            }

            String userJsonStr = objectMapper.writeValueAsString(map);
            JSONObject user = oneidDao.updateUser(poolId, poolSecret, userId, userJsonStr);
            if (user != null) {
                return result(HttpStatus.OK, null, "update base info success", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    @Override
    public ResponseEntity updatePhoto(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token, MultipartFile file) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        try {
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            JSONObject oldUser = oneidDao.getUser(poolId, poolSecret, userId, "id");
            String oldPhoto = jsonObjStringValue(oldUser, "photo");

            JSONObject user = oneidDao.updatePhoto(poolId, poolSecret, userId, file);
            if (user != null) {
                // 删除旧的头像
                authingUserDao.deleteObsObjectByUrl(oldPhoto);
                return result(HttpStatus.OK, null, "update photo success", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    @Override
    public ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String account = servletRequest.getParameter("account");
        String accountType = servletRequest.getParameter("account_type");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        try {
            String redisKey = account.toLowerCase() + "_sendCode_" + community;

            // 限制1分钟只能发送一次
            String codeOld = (String) redisDao.get(redisKey);
            if (codeOld != null) {
                return result(HttpStatus.BAD_REQUEST, null, "一分钟之内已发送过验证码", null);
            }

            String accountTypeCheck = getAccountType(account);
            if (!accountTypeCheck.equals("email") && !accountTypeCheck.equals("phone")) {
                return result(HttpStatus.BAD_REQUEST, null, accountTypeCheck, null);
            }

            // 发送验证码
            String[] strings = codeUtil.sendCode(accountType, account, mailSender, env, community.toLowerCase());
            if (StringUtils.isBlank(strings[0]) || !strings[2].equals("send code success"))
                return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);

            redisDao.set(redisKey, strings[0], Long.parseLong(strings[1]));
            return result(HttpStatus.OK, null, strings[2], null);
        } catch (Exception ex) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);
        }
    }

    @Override
    public ResponseEntity updateAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String oldAccount = servletRequest.getParameter("oldaccount");
        String oldCode = servletRequest.getParameter("oldcode");
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");

        if (StringUtils.isBlank(oldAccount) || StringUtils.isBlank(account) || StringUtils.isBlank(accountType) ||
                (!accountType.toLowerCase().equals("email") && !accountType.toLowerCase().equals("phone")))
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        if (accountType.toLowerCase().equals("email") && oldAccount.equals(account))
            return result(HttpStatus.BAD_REQUEST, null, "新邮箱与已绑定邮箱相同", null);
        else if (accountType.toLowerCase().equals("phone") && oldAccount.equals(account))
            return result(HttpStatus.BAD_REQUEST, null, "新手机号与已绑定手机号相同", null);

        try {
            // 验证码校验
            String redisKeyOld = oldAccount + "_sendCode_" + community;
            String codeTempOld = (String) redisDao.get(redisKeyOld);
            String codeCheckOld = checkCode(oldCode, codeTempOld);
            if (!codeCheckOld.equals("success"))
                return result(HttpStatus.BAD_REQUEST, null, codeCheckOld, null);
            // 验证码校验
            String redisKey = account + "_sendCode_" + community;
            String codeTemp = (String) redisDao.get(redisKey);
            String codeCheck = checkCode(code, codeTemp);
            if (!codeCheck.equals("success"))
                return result(HttpStatus.BAD_REQUEST, null, codeCheck, null);

            // 修改邮箱或者手机号
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            Object user = oneidDao.updateAccount(poolId, poolSecret, userId, oldAccount, account, accountType);
            if (user == null)
                return result(HttpStatus.BAD_REQUEST, null, "用户不存在", null);
            if (user instanceof JSONObject) {
                redisDao.updateValue(redisKey, codeTempOld + "_used", 0);
                redisDao.updateValue(redisKey, codeTemp + "_used", 0);
                return result(HttpStatus.OK, null, "update success", null);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, user.toString(), null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    @Override
    public ResponseEntity unbindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        // TODO 暂不支持解绑
        return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        /*String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");

        // todo 暂不支持解绑手机
        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType) ||
                (!accountType.toLowerCase().equals("email")*//* && !accountType.toLowerCase().equals("phone")*//*))
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        try {
            // 验证码校验
            String redisKey = account + "_sendCode_" + community;
            String codeTemp = (String) redisDao.get(redisKey);
            String codeCheck = checkCode(code, codeTemp);
            if (!codeCheck.equals("success"))
                return result(HttpStatus.BAD_REQUEST, null, codeCheck, null);

            // 解绑
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            Object user = oneidDao.updateAccount(poolId, poolSecret, userId, account, "", accountType);
            if (user == null)
                return result(HttpStatus.BAD_REQUEST, null, "用户不存在", null);
            if (user instanceof JSONObject) {
                redisDao.updateValue(redisKey, codeTemp + "_used", 0);
                return result(HttpStatus.OK, null, "unbind success", null);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, user.toString(), null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);*/
    }

    @Override
    public ResponseEntity bindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String account = servletRequest.getParameter("account");
        String code = servletRequest.getParameter("code");
        String accountType = servletRequest.getParameter("account_type");

        if (StringUtils.isBlank(account) || StringUtils.isBlank(accountType) ||
                (!accountType.toLowerCase().equals("email") && !accountType.toLowerCase().equals("phone")))
            return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        try {
            // 验证码校验
            String redisKey = account + "_sendCode_" + community;
            String codeTemp = (String) redisDao.get(redisKey);
            String codeCheck = checkCode(code, codeTemp);
            if (!codeCheck.equals("success"))
                return result(HttpStatus.BAD_REQUEST, null, codeCheck, null);

            // 绑定
            DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
            String userId = decode.getAudience().get(0);
            Object user = oneidDao.bindAccount(poolId, poolSecret, userId, account, accountType);
            if (user == null)
                return result(HttpStatus.BAD_REQUEST, null, "用户不存在", null);
            if (user instanceof JSONObject) {
                redisDao.updateValue(redisKey, codeTemp + "_used", 0);
                return result(HttpStatus.OK, null, "bind success", null);
            } else {
                return result(HttpStatus.BAD_REQUEST, null, user.toString(), null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    private String getAccountType(String account) {
        String accountTypeError = "请输入正确的手机号或者邮箱";
        if (StringUtils.isBlank(account)) {
            return accountTypeError;
        }
        if (account.matches(Constant.EMAILREGEX)) {
            return "email";
        }
        if (account.matches(Constant.PHONEREGEX)) {
            return "phone";
        }
        return accountTypeError;
    }

    private String checkPhoneAndEmail(String poolId, String poolSecret, String account) {
        String accountType = getAccountType(account);
        if (!accountType.equals("email") && !accountType.equals("phone"))
            return accountType;

        if (oneidDao.isUserExists(poolId, poolSecret, account, accountType))
            return "该账号已注册";
        else
            return accountType;
    }

    private Map<String, String> getApps() {
        HashMap<String, String> res = new HashMap<>();
        String property = env.getProperty("opengauss.apps");
        String[] split = property.split(";");
        for (String s : split) {
            String[] app = s.split(":");
            res.put(app[0], app[1]);
        }
        return res;
    }

    private List<String> getSendCodeChannel() {
        ArrayList<String> channels = new ArrayList<>();
        String property = env.getProperty("oneid.send.code.channel");
        for (String chanel : property.split(",")) {
            channels.add("channel_" + chanel);
        }
        return channels;
    }

    private ResponseEntity result(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data) {
        return result.setResult(status, msgCode, msg, data, error2code);
    }

    // JSONObject获取单个node的值
    private String jsonObjStringValue(JSONObject jsonObj, String nodeName) {
        String res = "";
        try {
            if (jsonObj.isNull(nodeName)) return res;
            Object obj = jsonObj.get(nodeName);
            if (obj != null) res = obj.toString();
        } catch (Exception ex) {
            System.out.println(nodeName + "Get Error");
        }
        return res;
    }

    // 解密RSA加密过的token
    private String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
        return RSAUtil.privateDecrypt(token, privateKey);
    }

    private ResponseEntity deleteUserAfter(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse,
                                           String token, String userId, Date issuedAt, String photo) {
        try {
            // 当前token失效
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 删除用户头像
            authingUserDao.deleteObsObjectByUrl(photo);

            // 删除cookie，删除idToken
            String headerToken = httpServletRequest.getHeader("token");
            String idTokenKey = "idToken_" + headerToken;
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(idTokenKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result(HttpStatus.OK, null, "delete user success", null);
    }

    private String checkCode(String code, String codeTemp) {
        if (code == null || codeTemp == null || codeTemp.endsWith("_used")) {
            return "验证码无效或已过期";
        }
        if (!codeTemp.equals(code)) {
            return "验证码不正确";
        }
        return "success";
    }
}
