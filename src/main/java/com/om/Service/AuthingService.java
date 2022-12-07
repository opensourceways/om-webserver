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

package com.om.Service;

import cn.authing.core.types.Application;
import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Utils.CodeUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Utils.RSAUtil;

import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.PostConstruct;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.om.Vo.OauthTokenVo;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;


@Service
public class AuthingService {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    QueryDao queryDao;

    @Autowired
    JavaMailSender mailSender;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    private static final String OIDCISSUER = "ONEID";

    private static CodeUtil codeUtil;

    private static Map<String, MessageCodeConfig> error2code;

    private static HashMap<String, Boolean> domain2secure;

    private static ObjectMapper objectMapper;

    private static final String PHONEREGEX = "^[a-z0-9]{11}$";

    private static final String EMAILREGEX = "^[A-Za-z0-9-._\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";

    private static HashMap<String, String[]> oidcScopeOthers;

    private static HashMap<String, String> oidcScopeAuthingMapping;

    @PostConstruct
    public void init() {
        codeUtil = new CodeUtil();
        error2code = authingUserDao.getErrorCode();
        objectMapper = new ObjectMapper();
        domain2secure = HttpClientUtils.getConfigCookieInfo(Objects.requireNonNull(env.getProperty("cookie.token.domains")), Objects.requireNonNull(env.getProperty("cookie.token.secures")));
        oidcScopeOthers = getOidcScopesOther();
        oidcScopeAuthingMapping = oidcScopeAuthingMapping();
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

    public ResponseEntity sendCodeV3(String account, String channel, boolean isSuccess) {
        // 验证码二次校验
        if (!isSuccess)
            return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);

        // 限制一分钟登录失败次数
        String loginErrorCountKey = account + "loginCount";
        Object v = redisDao.get(loginErrorCountKey);
        int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
        if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.count", "6")))
            return result(HttpStatus.BAD_REQUEST, null, "失败次数过多，请稍后重试", null);

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
        String msg;
        // 用户名校验
        msg = authingUserDao.checkUsername(userName);
        if (!msg.equals("success"))
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        if (StringUtils.isBlank(account))
            return result(HttpStatus.BAD_REQUEST, null, "邮箱不能为空", null);
        if (!account.matches(EMAILREGEX))
            return result(HttpStatus.BAD_REQUEST, null, "请输入正确的邮箱", null);

        // 邮箱 OR 手机号校验
        String accountType = checkPhoneAndEmail(account);

        if (accountType.equals("email")) {
            // 邮箱注册
            msg = authingUserDao.registerByEmail(account, code, userName);
        } /*else if (accountType.equals("phone")) {
            // 手机注册
            msg = authingUserDao.registerByPhone(account, code, userName);
        } */ else {
            return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        if (!msg.equals("success")) return result(HttpStatus.BAD_REQUEST, null, msg, null);

        return result(HttpStatus.OK, "success", null);
    }

    public ResponseEntity login(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse,
                                String community, String permission, String account, String code) {
        // 限制一分钟登录失败次数
        String loginErrorCountKey = account + "loginCount";
        Object v = redisDao.get(loginErrorCountKey);
        int loginErrorCount = v == null ? 0 : Integer.parseInt(v.toString());
        if (loginErrorCount >= Integer.parseInt(env.getProperty("login.error.count", "6")))
            return result(HttpStatus.BAD_REQUEST, null, "失败次数过多，请稍后重试", null);

        // 登录
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
            long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
            loginErrorCount += 1;
            redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
            return result(HttpStatus.BAD_REQUEST, null, (String) msg, null);
        }

        String userId;
        User user;
        try {
            DecodedJWT decode = JWT.decode(idToken);
            userId = decode.getSubject();
            user = authingUserDao.getUser(userId);
        } catch (Exception e) {
            long codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
            loginErrorCount += 1;
            redisDao.set(loginErrorCountKey, String.valueOf(loginErrorCount), codeExpire);
            return result(HttpStatus.BAD_REQUEST, null, "登录失败", null);
        }

        //登录成功解除登录失败次数限制
        redisDao.remove(loginErrorCountKey);

        // 资源权限
        String permissionInfo = env.getProperty(community + "." + permission);

        // 生成token
        String[] tokens = jwtTokenCreateService.authingUserToken(userId, permissionInfo, permission, idToken);
        String token = tokens[0];
        String verifyToken = tokens[1];

        // 写cookie
        String cookieTokenName = env.getProperty("cookie.token.name");
        String maxAgeTemp = env.getProperty("authing.cookie.max.age");
        int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : Integer.parseInt(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds")));
        HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, token, true, maxAge, "/", domain2secure);

        // 返回结果
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("token", verifyToken);
        userData.put("photo", user.getPhoto());
        userData.put("username", user.getUsername());
        userData.put("email_exist", StringUtils.isNotBlank(user.getEmail()));
        return result(HttpStatus.OK, "success", userData);
    }

    public ResponseEntity appVerify(String appId, String redirect) {
        List<String> uris = authingUserDao.getAppRedirectUris(appId);
        for (String uri : uris) {
            if (uri.endsWith("*") && redirect.startsWith(uri.substring(0, uri.length() - 1)))
                return result(HttpStatus.OK, "success", null);
            else if (redirect.equals(uri))
                return result(HttpStatus.OK, "success", null);
        }
        return result(HttpStatus.BAD_REQUEST, null, "回调地址与配置不符", null);
    }

    public ResponseEntity oidcAuthorize(String token, String appId, String redirectUri, String responseType, String state, String scope) {
        try {
            // responseType校验
            if (!responseType.equals("code"))
                return resultOidc(HttpStatus.NOT_FOUND, "currently response_type only supports code", null);

            // scope校验
            List<String> scopes = Arrays.asList(scope.split(" "));
            if (!scopes.contains("openid") || !scopes.contains("profile"))
                return resultOidc(HttpStatus.NOT_FOUND, "scope must contain <openid profile>", null);

            // app回调地址校验
            ResponseEntity responseEntity = appVerify(appId, redirectUri);
            if (responseEntity.getStatusCode().value() != 200)
                return resultOidc(HttpStatus.NOT_FOUND, "redirect_uri not found in the app", null);

            // 获取登录用户ID
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);

            // 生成code和state
            String code = codeUtil.randomStrBuilder(32);
            state = StringUtils.isNotBlank(state) ? state : UUID.randomUUID().toString().replaceAll("-", "");

            // 生成access_token和refresh_token
            scope = StringUtils.isBlank(scope) ? "openid profile" : scope;
            long codeExpire = Long.parseLong(env.getProperty("oidc.code.expire", "60"));
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, accessTokenExpire, null);
            String refreshToken = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, refreshTokenExpire, null);

            // 缓存 code
            HashMap<String, String> codeMap = new HashMap<>();
            codeMap.put("accessToken", accessToken);
            codeMap.put("refreshToken", refreshToken);
            codeMap.put("state", state);
            codeMap.put("appId", appId);
            codeMap.put("redirectUri", redirectUri);
            codeMap.put("scope", scope);
            String codeMapStr = "oidcCode:" + objectMapper.writeValueAsString(codeMap);
            redisDao.set(code, codeMapStr, codeExpire);
            // 缓存 oidcToken
            HashMap<String, String> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessToken);
            userTokenMap.put("refresh_token", refreshToken);
            userTokenMap.put("scope", scope);
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshToken.getBytes()), userTokenMapStr, refreshTokenExpire);

            String res = String.format("%s?code=%s&state=%s", redirectUri, code, state);
            return resultOidc(HttpStatus.OK, "OK", res);
        } catch (Exception e) {
            e.printStackTrace();
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    public ResponseEntity oidcToken(String appId, String appSecret, String grantType, String code, String state,
                                    String redirectUri, OauthTokenVo oauthTokenVo, String refreshToken) {
        try {
            if (grantType.equals("authorization_code"))
                return getOidcTokenByCode(appId, appSecret, code, state, redirectUri, oauthTokenVo);
            else if (grantType.equals("refresh_token"))
                return oidcRefreshToken(refreshToken);
            else
                return resultOidc(HttpStatus.BAD_REQUEST, "grant_type must be authorization_code or refresh_token", null);
        } catch (Exception e) {
            e.printStackTrace();
            redisDao.remove(code);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    public ResponseEntity userByAccessToken(String accessToken) {
        try {
            // 解析access_token
            String token = rsaDecryptToken(accessToken);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();

            // token是否被刷新了或者已经过期
            Object refreshedToken = redisDao.get(DigestUtils.md5DigestAsHex(accessToken.getBytes()));
            if (refreshedToken != null || expiresAt.before(new Date()))
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);

            // 获取用户
            JSONObject userObj = authingUserDao.getUserById(userId);

            // 根据scope获取用户信息 oidcScopeAuthingMapping(临时,字段映射)
            HashMap<String, Object> userData = new HashMap<>();
            HashMap<String, Object> addressMap = new HashMap<>();
            // 1、默认字段
            String[] profiles = env.getProperty("oidc.scope.profile", "").split(",");
            for (String profile : profiles) {
                String profileTemp = oidcScopeAuthingMapping.getOrDefault(profile, profile);
                Object value = jsonObjObjectValue(userObj, profileTemp);
                if (profile.equals("updated_at") && value != null) {
                    DateTimeFormatter df = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    value = LocalDateTime.parse(value.toString(), df).toInstant(ZoneOffset.UTC).toEpochMilli();
                }
                userData.put(profile, value);
            }
            // 2、指定字段
            String[] scopes = decode.getClaim("scope").asString().split(" ");
            for (String scope : scopes) {
                if (scope.equals("openid") || scope.equals("profile")) continue;
                String[] claims = oidcScopeOthers.getOrDefault(scope, new String[]{scope});
                for (String claim : claims) {
                    String profileTemp = oidcScopeAuthingMapping.getOrDefault(claim, claim);
                    Object value = jsonObjObjectValue(userObj, profileTemp);
                    if (scope.equals("address")) addressMap.put(claim, value);
                    else userData.put(claim, value);
                }
                if (scope.equals("address")) userData.put(scope, addressMap);
            }
            return resultOidc(HttpStatus.OK, "OK", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
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

    public ResponseEntity userPermissions(String community, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);

            // 获取权限
            ArrayList<String> permissions = new ArrayList<>();
            ArrayList<String> pers = authingUserDao.getUserPermission(userId, env.getProperty("openeuler.groupCode"));
            for (String per : pers) {
                String[] perList = per.split(":");
                if (perList.length > 1) {
                    permissions.add(perList[0] + perList[1]);
                }
            }

            //获取企业信息
            ArrayList<String> companyNameList = new ArrayList<>();
            JSONObject userObj = authingUserDao.getUserById(userId);            
            HashMap<String, Map<String, Object>> map = new HashMap<>();
            JSONArray jsonArray = userObj.getJSONArray("identities");
            for (Object o : jsonArray) {
                JSONObject obj =  (JSONObject) o;
                authingUserIdentityIdp(obj, map);
            }
            if (null != map.get("oauth2") && null != map.get("oauth2").get("login_name")) {
                String login = map.get("oauth2").get("login_name").toString();
                String company = queryDao.queryUserCompany(community, login);
                companyNameList = queryDao.getcompanyNameList(company);               
            }

            // 获取用户
            User user = authingUserDao.getUser(userId);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();

            userData.put("permissions", permissions);
            userData.put("username", user.getUsername());
            userData.put("companyList", companyNameList);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    public ResponseEntity logoutOld(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse, String token) {
        try {
            String headerToken = httpServletRequest.getHeader("token");
            String idTokenKey = "idToken_" + headerToken;
            String idToken = (String) redisDao.get(idTokenKey);

            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();

            // 退出登录，该token失效
            String redisKey = userId + issuedAt.toString();
            redisDao.set(redisKey, token, Long.valueOf(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds"))));

            // 退出登录，删除cookie，删除idToken
            String cookieTokenName = env.getProperty("cookie.token.name");
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, null, true, 0, "/", domain2secure);
            redisDao.remove(idTokenKey);

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
            String username = (String) user.get("username");
            String email = (String) user.get("email");

            // 资源权限
            String permissionInfo = env.getProperty(community + "." + permission);

            // 生成token
            String[] tokens = jwtTokenCreateService.authingUserToken(userId, permissionInfo, permission, idToken);
            String token = tokens[0];
            String verifyToken = tokens[1];

            // 写cookie
            String cookieTokenName = env.getProperty("cookie.token.name");
            String maxAgeTemp = env.getProperty("authing.cookie.max.age");
            int maxAge = StringUtils.isNotBlank(maxAgeTemp) ? Integer.parseInt(maxAgeTemp) : Integer.parseInt(Objects.requireNonNull(env.getProperty("authing.token.expire.seconds")));
            HttpClientUtils.setCookie(httpServletRequest, servletResponse, cookieTokenName, token, true, maxAge, "/", domain2secure);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("token", verifyToken);
            userData.put("photo", picture);
            userData.put("username", username);
            userData.put("email_exist", StringUtils.isNotBlank(email));
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

    public ResponseEntity deleteUser(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse, String token) {
        try {
            token = rsaDecryptToken(token);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date issuedAt = decode.getIssuedAt();
            String photo = authingUserDao.getUser(userId).getPhoto();

            //用户注销
            boolean res = authingUserDao.deleteUserById(userId);
            if (res) return deleteUserAfter(httpServletRequest, servletResponse, token, userId, issuedAt, photo);
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
            String code = codeUtil.randomNumBuilder(Integer.parseInt(env.getProperty("code.length", "6")));

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
                    String templateParas = String.format("[\"%s\",\"%s\"]", code, env.getProperty("msgsms.template.context.expire", "1"));
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
        if (type.toLowerCase().equals("email") && oldaccount.equals(account))
            return result(HttpStatus.BAD_REQUEST, null, "新邮箱与已绑定邮箱相同", null);
        else if (type.toLowerCase().equals("phone") && oldaccount.equals(account))
            return result(HttpStatus.BAD_REQUEST, null, "新手机号与已绑定手机号相同", null);

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
        String msg = authingUserDao.unLinkAccount(token, platform);
        if (!msg.equals("success")) {
            return result(HttpStatus.BAD_REQUEST, null, msg, null);
        }
        return result(HttpStatus.OK, "unlink account success", null);
    }

    public ResponseEntity updateUserBaseInfo(String token, Map<String, Object> map) {
        String res = authingUserDao.updateUserBaseInfo(token, map);
        if (res.equals("success")) return result(HttpStatus.OK, "update base info success", null);
        else return result(HttpStatus.BAD_REQUEST, null, res, null);
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

    // JSONObject获取单个node的值
    private Object jsonObjObjectValue(JSONObject jsonObj, String nodeName) {
        Object res = null;
        try {
            if (jsonObj.isNull(nodeName)) return res;
            Object obj = jsonObj.get(nodeName);
            if (obj != null) res = obj;
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

    private ResponseEntity resultOidc(HttpStatus status, String msg, Object body) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("status", status.value());
        res.put("message", msg);
        if (body != null)
            res.put("body", body);
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
                return result(HttpStatus.BAD_REQUEST, null, "请求异常", null);
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
        return result(HttpStatus.OK, "delete user success", null);
    }

    private HashMap<String, String[]> getOidcScopesOther() {
        String[] others = env.getProperty("oidc.scope.other", "").split(";");
        HashMap<String, String[]> otherMap = new HashMap<>();
        for (String other : others) {
            if (StringUtils.isBlank(other)) continue;
            String[] split = other.split("->");
            otherMap.put(split[0], split[1].split(","));
        }
        return otherMap;
    }

    private HashMap<String, String> oidcScopeAuthingMapping() {
        String[] mappings = env.getProperty("oidc.scope.authing.mapping", "").split(",");
        HashMap<String, String> authingMapping = new HashMap<>();
        for (String mapping : mappings) {
            if (StringUtils.isBlank(mapping)) continue;
            String[] split = mapping.split(":");
            authingMapping.put(split[0], split[1]);
        }
        return authingMapping;
    }

    private ResponseEntity getOidcTokenByCode(String appId, String appSecret, String code, String state,
                                              String redirectUri, OauthTokenVo oauthTokenVo) {
        try {
            if (oauthTokenVo != null) {
                appId = oauthTokenVo.getApp_id() == null ? appId : oauthTokenVo.getApp_id();
                appSecret = oauthTokenVo.getApp_secret() == null ? appSecret : oauthTokenVo.getApp_secret();
            }
            // 参数校验
            if (StringUtils.isBlank(appId) || StringUtils.isBlank(appSecret))
                return resultOidc(HttpStatus.BAD_REQUEST, "not found the app", null);
            // 用户code获取token必须包含code、state、redirectUri
            if (StringUtils.isBlank(code) || StringUtils.isBlank(state) || StringUtils.isBlank(redirectUri))
                return resultOidc(HttpStatus.BAD_REQUEST, "when grant_type is authorization_code,parameters must contain code、state、redirectUri", null);

            // 授权码校验
            String codeMapStr = (String) redisDao.get(code);
            if (StringUtils.isBlank(codeMapStr))
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);

            // 授权码信息
            com.fasterxml.jackson.databind.JsonNode jsonNode = objectMapper.readTree(codeMapStr.replace("oidcCode:", ""));
            String appIdTemp = jsonNode.get("appId").asText();
            String stateTemp = jsonNode.get("state").asText();
            String redirectUriTemp = jsonNode.get("redirectUri").asText();
            String scopeTemp = jsonNode.get("scope").asText();

            // 授权码state校验
            if (!state.equals(stateTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "state error", null);
            }
            // app校验（授权码对应的app）
            if (!appId.equals(appIdTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);
            }
            // app回调地址校验（授权码对应的app的回调地址）
            if (!redirectUri.equals(redirectUriTemp)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.BAD_REQUEST, "code invalid or expired", null);
            }
            // app密码校验
            Application app = authingUserDao.getAppById(appId);
            if (app == null || !app.getSecret().equals(appSecret)) {
                redisDao.remove(code);
                return resultOidc(HttpStatus.NOT_FOUND, "app invalid or secret error", null);
            }

            HashMap<String, String> tokens = new HashMap<>();
            tokens.put("scope", scopeTemp);
            tokens.put("access_token", jsonNode.get("accessToken").asText());
            if (Arrays.asList(scopeTemp.split(" ")).contains("offline_access"))
                tokens.put("refresh_token", jsonNode.get("refreshToken").asText());

            redisDao.remove(code);
            return resultOidc(HttpStatus.OK, "OK", tokens);
        } catch (Exception e) {
            e.printStackTrace();
            redisDao.remove(code);
            return resultOidc(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", null);
        }
    }

    private ResponseEntity oidcRefreshToken(String refreshToken) {
        try {
            if (StringUtils.isBlank(refreshToken))
                return resultOidc(HttpStatus.BAD_REQUEST, "when grant_type is authorization_code,parameters must contain refresh_token", null);

            // 解析refresh_token
            String token = rsaDecryptToken(refreshToken);
            DecodedJWT decode = JWT.decode(token);
            String userId = decode.getAudience().get(0);
            Date expiresAt = decode.getExpiresAt();

            // tokens校验
            String refreshTokenKey = DigestUtils.md5DigestAsHex(refreshToken.getBytes());
            String tokenStr = (String) redisDao.get(refreshTokenKey);
            if (StringUtils.isBlank(tokenStr))
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
            // refresh_token是否过期
            if (expiresAt.before(new Date()))
                return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);

            com.fasterxml.jackson.databind.JsonNode jsonNode = objectMapper.readTree(tokenStr.replace("oidcTokens:", ""));
            String scope = jsonNode.get("scope").asText();
            String accessToken = jsonNode.get("access_token").asText();

            // 生成新的accessToken和refreshToken
            long accessTokenExpire = Long.parseLong(env.getProperty("oidc.access.token.expire", "1800"));
            long refreshTokenExpire = Long.parseLong(env.getProperty("oidc.refresh.token.expire", "86400"));
            String accessTokenNew = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, accessTokenExpire, null);
            String refreshTokenNew = jwtTokenCreateService.oidcToken(userId, OIDCISSUER, scope, refreshTokenExpire, expiresAt);

            // 缓存新的accessToken和refreshToken
            HashMap<String, String> userTokenMap = new HashMap<>();
            userTokenMap.put("access_token", accessTokenNew);
            userTokenMap.put("refresh_token", refreshTokenNew);
            userTokenMap.put("scope", scope);
            String userTokenMapStr = "oidcTokens:" + objectMapper.writeValueAsString(userTokenMap);
            redisDao.set(DigestUtils.md5DigestAsHex(refreshTokenNew.getBytes()), userTokenMapStr, refreshTokenExpire);

            // 移除以前的refresh_token，并将之前的access_token失效
            redisDao.remove(refreshTokenKey);
            redisDao.set(DigestUtils.md5DigestAsHex(accessToken.getBytes()), accessToken, accessTokenExpire);

            return resultOidc(HttpStatus.OK, "OK", userTokenMap);
        } catch (Exception e) {
            e.printStackTrace();
            return resultOidc(HttpStatus.BAD_REQUEST, "token invalid or expired", null);
        }
    }
}
