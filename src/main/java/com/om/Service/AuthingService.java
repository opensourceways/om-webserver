package com.om.Service;

import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
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
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AuthingService {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    JavaMailSender mailSender;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    private static CodeUtil codeUtil;

    private static Map<String, MessageCodeConfig> error2code;

    private static HashMap<String, Boolean> domain2secure;

    private static final String PHONEREGEX = "^[a-z0-9]{11}$";

    private static final String EMAILREGEX = "^[A-Za-z0-9-_\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";

    @PostConstruct
    public void init() {
        codeUtil = new CodeUtil();
        error2code = authingUserDao.getErrorCode();
        domain2secure = HttpClientUtils.getConfigCookieInfo(Objects.requireNonNull(env.getProperty("cookie.token.domains")), Objects.requireNonNull(env.getProperty("cookie.token.secures")));
    }

    public ResponseEntity accountExists(String userName, String account) {
        if (StringUtils.isNotBlank(userName)) {
            boolean username = authingUserDao.isUserExists(userName, "username");
            if (username) return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);
        } else if (StringUtils.isNotBlank(account)) {
            String accountType = checkPhoneAndEmail(account);
            if (!accountType.equals("email") && !accountType.equals("phone"))
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity sendCodeV3(String account, String channel) {
        if (!channel.equalsIgnoreCase("channel_login") && !channel.equalsIgnoreCase("channel_register")) {
            return result(HttpStatus.BAD_REQUEST, null, "仅登录和注册使用", null);
        }

        String accountType = getAccountType(account);
        String msg = "";
        if (accountType.equals("email"))
            msg = authingUserDao.sendEmailCodeV3(account, channel);
        else if (accountType.equals("phone"))
            msg = authingUserDao.sendPhoneCodeV3(account, channel);
        else
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);

        if (!msg.equals("success")) return result(HttpStatus.BAD_REQUEST, null, msg, null);
        else return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity register(String userName, String account, String code) {
        // 用户名校验
        if (StringUtils.isBlank(userName))
            return result(HttpStatus.BAD_REQUEST, null, "用户名不能为空", null);
        if (authingUserDao.isUserExists(userName, "username"))
            return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);

        if (StringUtils.isBlank(account))
            return result(HttpStatus.BAD_REQUEST, null, "手机号或者邮箱不能为空", null);

        // 邮箱 OR 手机号校验
        String accountType = checkPhoneAndEmail(account);

        String msg;
        if (accountType.equals("email")) {
            // 邮箱注册
            msg = authingUserDao.registerByEmail(account, code, userName);
        } else if (accountType.equals("phone")) {
            // 手机注册
            msg = authingUserDao.registerByPhone(account, code, userName);
        } else {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        if (!msg.equals("success")) return result(HttpStatus.BAD_REQUEST, null, msg, null);

        return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity login(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse,
                                String community, String permission, String account, String code) {
        String accountType = getAccountType(account);

        Object msg = null;
        if (accountType.equals("email")) {
            msg = authingUserDao.loginByEmailCode(account, code);
        } else if (accountType.equals("phone")) {
            msg = authingUserDao.loginByPhoneCode(account, code);
        } else {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }

        String idToken;
        if (msg instanceof JSONObject) {
            JSONObject user = (JSONObject) msg;
            idToken = user.getString("id_token");
        } else {
            return result(HttpStatus.BAD_REQUEST, null, (String) msg, null);
        }

        String userId;
        User user;
        try {
            DecodedJWT decode = JWT.decode(idToken);
            userId = decode.getSubject();
            user = authingUserDao.getUser(userId);
        } catch (Exception e) {
            return result(HttpStatus.BAD_REQUEST, null, "登录失败", null);
        }

        // 资源权限
        String permissionInfo = env.getProperty(community + "." + permission);

        // 生成token
        String[] tokens = jwtTokenCreateService.authingUserToken(userId, permissionInfo, permission, idToken);
        String token = tokens[0];
        String verifyToken = tokens[1];

        // 写cookie
        String cookieTokenName = env.getProperty("cookie.token.name");
        int maxAge = Integer.parseInt(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds")));
        HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, token, true, maxAge, "/", domain2secure);

        // 返回结果
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", verifyToken);
        userData.put("photo", user.getPhoto());
        userData.put("username", user.getUsername());
        return result(HttpStatus.OK, "success", userData);
    }

    public ResponseEntity authingUserPermission(String community, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            String permissionTemp = decode.getClaim("permission").asString();
            String inputPermission = decode.getClaim("inputPermission").asString();

            // 资源权限验证
            String permissionToken = new String(Base64.getDecoder().decode(permissionTemp.getBytes()));
            ArrayList<String> permissions = new ArrayList<>();
            String[] split = permissionToken.split("->");
            boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
            if (hasActionPer) {
                permissions.add(inputPermission);
            }

            // 获取用户
            User user = authingUserDao.getUser(userId);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("photo", user.getPhoto());
            userData.put("permissions", permissions);
            userData.put("username", user.getUsername());
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    public ResponseEntity logoutOld(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String headerToken = httpServletRequest.getHeader("token");
            String idToken = (String) redisDao.get("idToken_" + headerToken);

            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 退出登录，删除cookie，删除idToken
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(headerToken);

            HashMap<String, Object> userData = new HashMap<>();
            userData.put("id_token", idToken);

            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    // 后端退出，目前有误 TODO
    public ResponseEntity logout(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse, String token) {
        boolean res;
        String userId;
        Date issuedAt;
        String headerToken;
        try {
            // 解析token
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            userId = decode.getAudience().get(0);
            issuedAt = decode.getIssuedAt();

            // 获取用户idToken
            headerToken = httpServletRequest.getHeader("token");
            String idToken = (String) redisDao.get("idToken_" + headerToken);

            res = authingUserDao.logout(idToken, userId);
        } catch (Exception e) {
            return result(HttpStatus.BAD_REQUEST, null, "退出登录失败", null);
        }

        if (res) {
            // 退出登录，该token失效
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 退出登录，删除cookie
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(headerToken);
        }

        return result(HttpStatus.OK, "logout success", null);
    }


    public ResponseEntity tokenApply(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse,
                                     String community, String code, String permission, String redirectUrl) {
        try {
            // 将URL中的中文转码，因为@RequestParam会自动解码，而我们需要未解码的参数
            String url = redirectUrl;
            Matcher matcher = Pattern.compile("[\\u4e00-\\u9fa5]+").matcher(redirectUrl);
            String tmp = "";
            while (matcher.find()) {
                tmp = matcher.group();
                System.out.println(tmp);
                url = url.replaceAll(tmp, URLEncoder.encode(tmp, "UTF-8"));
            }

            // 通过code获取access_token，再通过access_token获取用户
            Map user = authingUserDao.getUserInfoByAccessToken(code, url);
            if (user == null) return result(HttpStatus.UNAUTHORIZED, "user not found", null);
            String userId = user.get("sub").toString();
            String idToken = user.get("id_token").toString();
            String picture = user.get("picture").toString();
            String username = user.get("username").toString();

            // 资源权限
            String permissionInfo = env.getProperty(community + "." + permission);

            // 生成token
            String[] tokens = jwtTokenCreateService.authingUserToken(userId, permissionInfo, permission, idToken);
            String token = tokens[0];
            String verifyToken = tokens[1];

            // 写cookie
            String cookieTokenName = env.getProperty("cookie.token.name");
            int maxAge = Integer.parseInt(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds")));
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, token, true, maxAge, "/", domain2secure);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", verifyToken);
            userData.put("photo", picture);
            userData.put("username", username);
            return result(HttpStatus.OK, "success", userData);

        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    public ResponseEntity personalCenterUserInfo(String token) {
        try {
            String userId = getUserIdFromToken(token);
            JSONObject userObj = authingUserDao.getUserById(userId);
            HashMap<String, Object> userData = parseAuthingUser(userObj);
            // 返回结果
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }

    }

    public ResponseEntity deleteUser(String token) {
        try {
            String userId = getUserIdFromToken(token);
            boolean res = authingUserDao.deleteUserById(userId);
            if (res) return result(HttpStatus.OK, "delete user success", null);
            else return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        } catch (Exception e) {
            return result(HttpStatus.UNAUTHORIZED, null, "注销用户失败", null);
        }
    }

    public ResponseEntity sendCode(String account, String type, String field) {
        boolean res = authingUserDao.sendCode(account, type, field);
        if (!res) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);
        }
        return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity sendCodeUnbind(String account, String type) {
        String redisKey = account + "_CodeUnbind";
        try {
            // 限制1分钟只能发送一次
            String codeOld = (String) redisDao.get(redisKey);
            if (codeOld != null) {
                return result(HttpStatus.BAD_REQUEST, null, "一分钟之内已发送过验证码", null);
            }

            String resMsg = "send code fail";
            long codeExpire = 60L;

            // 生成验证码
            String code = codeUtil.randomNumBuilder();

            switch (type.toLowerCase()) {
                case "email":
                    codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
                    // 邮件服务器
                    String from = env.getProperty("spring.mail.username");
                    // 邮件信息
                    String[] info = codeUtil.buildEmailUnbindInfo(account, code);
                    // 发送验证码
                    resMsg = codeUtil.sendSimpleMail(mailSender, from, account, info[0], info[1]);
                    break;
                case "phone":
                    codeExpire = Long.parseLong(env.getProperty("msgsms.code.expire", "60"));
                    // 短信发送服务器
                    String msgsms_app_key = env.getProperty("msgsms.app_key");
                    String msgsms_app_secret = env.getProperty("msgsms.app_secret");
                    String msgsms_url = env.getProperty("msgsms.url");
                    String msgsms_signature = env.getProperty("msgsms.signature");
                    String msgsms_sender = env.getProperty("msgsms.sender");
                    String msgsms_template_id = env.getProperty("msgsms.template.id");
                    // 短信发送请求
                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                    String format = dtf.format(LocalDateTime.now());
                    String[] split = format.split(" ");
                    String templateParas = String.format("[\"%s\",\"%s\",\"%s\"]", code, split[0], split[1]);
                    String wsseHeader = codeUtil.buildWsseHeader(msgsms_app_key, msgsms_app_secret);
                    String body = codeUtil.buildSmsBody(msgsms_sender, account, msgsms_template_id, templateParas, "", msgsms_signature);
                    // 发送验证码
                    HttpResponse<JsonNode> response = Unirest.post(msgsms_url)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Authorization", CodeUtil.AUTH_HEADER_VALUE)
                            .header("X-WSSE", wsseHeader)
                            .body(body)
                            .asJson();
                    if (response.getStatus() == 200) resMsg = "send sms code success";
                    break;
                default:
                    break;
            }
            System.out.println("***** codeExpire: " + codeExpire);
            redisDao.set(redisKey, code, codeExpire);
            return result(HttpStatus.OK, resMsg, null);
        } catch (Exception ex) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);
        }
    }

    // 未使用
    public ResponseEntity resetPassword(String account, String code, String ps, String type) {
        boolean res = authingUserDao.changePassword(account, code, ps, type);
        if (!res) {
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
        return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity updateAccount(String token, String oldaccount, String oldcode, String account, String code, String type) {
        String res = authingUserDao.updateAccount(token, oldaccount, oldcode, account, code, type);
        return message(res);
    }

    public ResponseEntity unbindAccount(String token, String account, String code, String type) {
        String redisKey = account + "_CodeUnbind";
        String codeTemp = (String) redisDao.get(redisKey);
        if (codeTemp == null) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码无效或已过期", null);
        }
        if (!codeTemp.equals(code)) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);
        }
        String res = authingUserDao.unbindAccount(token, account, type);

        if (res.equals("unbind success")) {
            redisDao.remove(redisKey);
            return result(HttpStatus.OK, res, null);
        }
        return result(HttpStatus.BAD_REQUEST, null, res, null);
    }

    public ResponseEntity bindAccount(String token, String account, String code, String type) {
        String res = authingUserDao.bindAccount(token, account, code, type);
        return message(res);
    }

    public ResponseEntity linkConnList(String token) {
        List<Map<String, String>> res = authingUserDao.linkConnList(token);
        if (res == null) {
            return result(HttpStatus.UNAUTHORIZED, "get connections fail", null);
        }
        return result(HttpStatus.OK, "get connections success", res);
    }

    public ResponseEntity linkAccount(String token, String secondtoken) {
        String res = authingUserDao.linkAccount(token, secondtoken);
        return message(res);
    }

    public ResponseEntity unLinkAccount(String token, String platform) {
        boolean res = authingUserDao.unLinkAccount(token, platform);
        if (!res) {
            return result(HttpStatus.BAD_REQUEST, null, "解绑三方账号失败", null);
        }
        return result(HttpStatus.OK, "unlink account success", null);
    }

    public ResponseEntity updateUserBaseInfo(String token, Map<String, Object> map) {
        boolean res = authingUserDao.updateUserBaseInfo(token, map);
        if (res) return result(HttpStatus.OK, "update base info success", null);
        else return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    public ResponseEntity updatePhoto(String token, MultipartFile file) {
        boolean res = authingUserDao.updatePhoto(token, file);
        if (res) return result(HttpStatus.OK, "update photo success", null);
        else return result(HttpStatus.BAD_REQUEST, null, "更新失败", null);
    }

    // 获取自定义token中的user id
    private String getUserIdFromToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        DecodedJWT decode = JWT.decode(rsaDecryptToken(token));
        return decode.getAudience().get(0);
    }

    // 解密RSA加密过的token
    private String rsaDecryptToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
        return RSAUtil.privateDecrypt(token, privateKey);
    }

    // 解析authing user
    private HashMap<String, Object> parseAuthingUser(JSONObject userObj) {
        HashMap<String, Object> userData = new HashMap<>();

        userData.put("userName", jsonObjStringValue(userObj, "username"));
        userData.put("email", jsonObjStringValue(userObj, "email"));
        userData.put("phone", jsonObjStringValue(userObj, "phone"));
        userData.put("signedUp", jsonObjStringValue(userObj, "signedUp"));
        userData.put("nickName", jsonObjStringValue(userObj, "nickname"));
        userData.put("company", jsonObjStringValue(userObj, "company"));
        userData.put("photo", jsonObjStringValue(userObj, "photo"));
        ArrayList<Map<String, Object>> identities = authingUserIdentity(userObj);
        userData.put("identities", identities);

        return userData;
    }

    // identities 解析（包括gitee,github,wechat）
    private ArrayList<Map<String, Object>> authingUserIdentity(JSONObject userObj) {
        ArrayList<Map<String, Object>> res = new ArrayList<>();
        HashMap<String, Map<String, Object>> map = new HashMap<>();
        try {
            JSONArray jsonArray = userObj.getJSONArray("identities");
            for (Object o : jsonArray) {
                JSONObject obj = (JSONObject) o;
                authingUserIdentityIdp(obj, map);
            }
            res.addAll(map.values());
        } catch (Exception ex) {
            System.out.println("Identities Get Error");
        }
        return res;
    }

    // identities -> userInfoInIdp 解析（包括gitee,github,wechat）
    private void authingUserIdentityIdp(JSONObject identityObj, HashMap<String, Map<String, Object>> map) {
        HashMap<String, Object> res = new HashMap<>();

        JSONObject userInfoInIdpObj = identityObj.getJSONObject("userInfoInIdp");
//        String accessToken = jsonObjStringValue(identityObj, "accessToken");
        String provider = jsonObjStringValue(identityObj, "provider");
        switch (provider) {
            case "github":
                String github_login = jsonObjStringValue(userInfoInIdpObj, "profile").replace("https://api.github.com/users/", "");
                res.put("identity", "github");
                res.put("login_name", github_login);
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "username"));
                res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
                map.put(provider, res);
                break;
            case "oauth2":
                String gitee_login = userInfoInIdpObj.getJSONObject("customData").getString("giteeLogin");
                res.put("identity", "gitee");
                res.put("login_name", gitee_login);
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "name"));
                res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
                map.put(provider, res);
                break;
            case "wechat":
                res.put("identity", "wechat");
                res.put("login_name", "");
                res.put("user_name", jsonObjStringValue(userInfoInIdpObj, "nickname"));
                res.put("accessToken", jsonObjStringValue(userInfoInIdpObj, "accessToken"));
                map.put(provider, res);
                break;
            default:
                break;
        }
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

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        return new ResponseEntity<>(res, status);
    }

    private ResponseEntity result(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);

        if (status.value() == 400 && msgCode == null) {
            for (Map.Entry<String, MessageCodeConfig> entry : error2code.entrySet()) {
                if (msg.contains(entry.getKey())) {
                    msgCode = entry.getValue();
                    break;
                }
            }
        }

        if (msgCode != null) {
            HashMap<String, Object> msgMap = new HashMap<>();
            msgMap.put("code", msgCode.getCode());
            msgMap.put("message_en", msgCode.getMsgEn());
            msgMap.put("message_zh", msgCode.getMsgZh());
            res.put("msg", msgMap);
        }
        return new ResponseEntity<>(res, status);
    }

    private ResponseEntity message(String res) {
        switch (res) {
            case "true":
                return result(HttpStatus.OK, "success", null);
            case "false":
                return result(HttpStatus.BAD_REQUEST, null, "操作异常", null);
            default:
                ObjectMapper objectMapper = new ObjectMapper();
                String message = "faild";
                try {
                    res = res.substring(14);
                    Iterator<com.fasterxml.jackson.databind.JsonNode> buckets = objectMapper.readTree(res).iterator();
                    if (buckets.hasNext()) {
                        message = buckets.next().get("message").get("message").asText();
                    }
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                    message = e.getMessage();
                }
                return result(HttpStatus.BAD_REQUEST, null, message, null);
        }
    }

    private String getAccountType(String account) {
        String accountType;
        if (account.matches(EMAILREGEX))
            accountType = "email";
        else if (account.matches(PHONEREGEX))
            accountType = "phone";
        else
            accountType = "请输入正确的手机号或者邮箱";

        return accountType;
    }

    private String checkPhoneAndEmail(String account) {
        String accountType = getAccountType(account);
        if (!accountType.equals("email") && !accountType.equals("phone"))
            return accountType;

        if (authingUserDao.isUserExists(account, accountType))
            return "该账号已注册";
        else
            return accountType;
    }
}
