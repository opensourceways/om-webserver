package com.om.config;

import com.om.Result.Constant;
import com.om.Utils.HttpClientUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.util.HashMap;

@Configuration
public class LoginConfig {

    private final Environment environment;

    public static HashMap<String, Boolean> DOMAIN_TO_SECURE;

    public static String OIDC_LOGIN_PAGE;

    public static String OIDC_REGISTER_PAGE;

    public static long OIDC_CODE_EXPIRE;

    public static long OIDC_ACCESS_TOKEN_EXPIRE;

    public static long OIDC_REFRESH_TOKEN_EXPIRE;

    public static String[] OIDC_SCOPE_PROFILE;

    public static String COOKIE_TOKEN_NAME;

    public static String COOKIE_VERIFY_TOKEN_NAME;

    public static String AUTHING_COOKIE_MAX_AGE;

    public static int AUTHING_TOKEN_EXPIRE_SECONDS;

    public static String[] OIDC_SCOPE_AUTHING_MAPPING;

    public static String[] OIDC_SCOPE_OTHER;

    public static String RAS_AUTHING_PRIVATE_KEY;

    public static int LOGIN_ERROR_LIMIT_COUNT;

    public static long MAIL_CODE_EXPIRE;


    @Autowired
    public LoginConfig(Environment environment) {
        this.environment = environment;
    }


    @PostConstruct
    public void init() {
        String cookieDomains = environment.getProperty("cookie.token.domains");
        String cookieSecures = environment.getProperty("cookie.token.secures");

        if (StringUtils.hasText(cookieDomains) && StringUtils.hasText(cookieSecures)) {
            DOMAIN_TO_SECURE = HttpClientUtils.getConfigCookieInfo(cookieDomains, cookieSecures);
        }

        OIDC_LOGIN_PAGE = environment.getProperty("oidc.login.page");
        OIDC_REGISTER_PAGE = environment.getProperty("oidc.register.page");
        OIDC_CODE_EXPIRE = Long.parseLong(environment.getProperty("oidc.code.expire", "60"));
        OIDC_ACCESS_TOKEN_EXPIRE = Long.parseLong(environment.getProperty("oidc.access.token.expire", "1800"));
        OIDC_REFRESH_TOKEN_EXPIRE = Long.parseLong(environment.getProperty("oidc.refresh.token.expire", "86400"));
        OIDC_SCOPE_PROFILE = environment.getProperty("oidc.scope.profile", "").split(",");
        COOKIE_TOKEN_NAME = environment.getProperty("cookie.token.name");
        COOKIE_VERIFY_TOKEN_NAME = environment.getProperty("cookie.verify.token.name");
        AUTHING_COOKIE_MAX_AGE = environment.getProperty("authing.cookie.max.age");
        AUTHING_TOKEN_EXPIRE_SECONDS = Integer.parseInt(environment.getProperty("authing.token.expire.seconds", Constant.DEFAULT_EXPIRE_SECOND));
        OIDC_SCOPE_AUTHING_MAPPING = environment.getProperty("oidc.scope.authing.mapping", "").split(",");
        OIDC_SCOPE_OTHER = environment.getProperty("oidc.scope.other", "").split(";");
        RAS_AUTHING_PRIVATE_KEY = environment.getProperty("rsa.authing.privateKey");
        LOGIN_ERROR_LIMIT_COUNT = Integer.parseInt(environment.getProperty("login.error.limit.count", "6"));
        MAIL_CODE_EXPIRE = Long.parseLong(environment.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
    }
}
