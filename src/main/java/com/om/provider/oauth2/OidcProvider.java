package com.om.provider.oauth2;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Modules.MessageCodeConfig;
import com.om.Modules.UserIdentity;
import com.om.Result.Result;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@Primary
@Repository
public class OidcProvider {
    @Autowired
    protected Environment env;

    protected Result result;
    protected String name;
    protected String clientId;
    protected String clientSecret;
    protected String scope;
    protected String callback;
    protected String authorizationEndpoint;
    protected String tokenEndpoint;
    protected String userEndpoint;
    protected String emailsEndpoint;

    @PostConstruct
    public void init() {
        // TODO 从数据库获取并初始化OidcProvider
        result = new Result();
        name = this.getClass().getAnnotation(Repository.class).value();
        clientId = env.getProperty(name + ".client.id");
        clientSecret = env.getProperty(name + ".client.secret");
        scope = env.getProperty(name + ".scope");
        callback = env.getProperty(name + ".callback");
        authorizationEndpoint = env.getProperty(name + ".authorization.endpoint");
        tokenEndpoint = env.getProperty(name + ".token.endpoint");
        userEndpoint = env.getProperty(name + ".user.endpoint");
        emailsEndpoint = env.getProperty(name + ".emails.endpoint");
    }

    public String getName() {
        return name;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getScope() {
        return scope;
    }

    public String getCallback() {
        return callback;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getUserEndpoint() {
        return userEndpoint;
    }

    public String getEmailsEndpoint() {
        return emailsEndpoint;
    }

    /**
     * 跳转三方授权页面
     *
     * @param request      request
     * @param response     response
     * @param oidcProvider provider
     * @return str
     */
    public ResponseEntity oidcAuthorize(HttpServletRequest request, HttpServletResponse response,
                                        OidcProvider oidcProvider) {
        try {
            if (oidcProvider == null) {
                return result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00051);
            }

            // TODO 校验app
            String appId = request.getParameter("app_id");
            if (StringUtils.isBlank(appId) || !appId.equalsIgnoreCase("1234567")) {
                return result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00047);
            }

            String redirectUriEncode = redirectUriEncode(request, oidcProvider);
            String format = String.format("%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%s",
                    oidcProvider.getAuthorizationEndpoint(), oidcProvider.getClientId(),
                    oidcProvider.getScope(), redirectUriEncode);
            response.sendRedirect(format);

            return result.setResult(HttpStatus.OK, null);
        } catch (Exception e) {
            return result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00048);
        }
    }

    /**
     * 通过code获取access_token
     *
     * @param request      request
     * @param oidcProvider provider
     * @return access_token
     */
    public String getAccessTokenByCode(HttpServletRequest request, OidcProvider oidcProvider) {
        try {
            String redirectUriEncode = redirectUriEncode(request, oidcProvider);
            String requestUrl = String.format("%s?grant_type=authorization_code&code=%s&redirect_uri=%s",
                    oidcProvider.getTokenEndpoint(), request.getParameter("code"), redirectUriEncode);
            String body = String.format("{\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
                    oidcProvider.getClientId(), oidcProvider.getClientSecret());

            HttpResponse<JsonNode> res = Unirest.post(requestUrl)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .body(body)
                    .asJson();
            return res.getBody().getObject().getString("access_token");
        } catch (Exception e) {
            return "Internal Server Error";
        }
    }

    /**
     * 通过access_token获取用户信息
     * 初始化UserIdentity
     *
     * @param oidcProvider provider
     * @param accessToken  access_token
     * @return UserIdentity
     */
    public Object getUserByAccessToken(OidcProvider oidcProvider, String accessToken) {
        try {
            HttpResponse<JsonNode> res = Unirest.get(oidcProvider.getUserEndpoint())
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .asJson();
            JSONObject bodyObj = res.getBody().getObject();
            return oidcProvider.initUserIdentity(bodyObj, accessToken);
        } catch (Exception e) {
            return "Internal Server Error";
        }
    }

    /**
     * 初始化UserIdentity
     *
     * @param userObj     三方用户信息
     * @param accessToken access_token
     * @return UserIdentity
     */
    protected UserIdentity initUserIdentity(JSONObject userObj, String accessToken) {
        return new UserIdentity()
                .setUserIdInIdp(userObj.get("id"))
                .setAccessToken(accessToken);
    }

    /**
     * 设置redirectUri参数并进行url编码
     *
     * @param request      request
     * @param oidcProvider provider
     * @return 编码后的redirectUri
     */
    private String redirectUriEncode(HttpServletRequest request, OidcProvider oidcProvider)
            throws UnsupportedEncodingException {
        String callback = String.format(oidcProvider.getCallback(), oidcProvider.getName());
        String redirectUri = callback
                + "?community=" + request.getParameter("community")
                + "&app_id=" + request.getParameter("app_id");
        return URLEncoder.encode(redirectUri, "utf-8");
    }

}
