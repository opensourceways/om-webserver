package com.om.Service.impl;

import com.om.Dao.oneId.OneIdAppDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Result;
import com.om.Service.inter.OidcServiceInter;
import com.om.Vo.dto.OidcAuthorize;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@ConditionalOnProperty(value = "service.oidc", havingValue = "oidcServiceImplOneId")
public class OidcServiceImplOneId implements OidcServiceInter {

    @Autowired
    private Environment environment;

    @Autowired
    OneIdAppDao oneIdAppDao;


    public final static List<String> RESPONSE_TYPE_AVAILABLE = Collections.singletonList("code");

    public final static List<String> SCOPE_AVAILABLE = Arrays.asList("openid", "profile", "email", "phone", "address", "offline_access");

    @Override
    public ResponseEntity<?> oidcAuthorize(OidcAuthorize oidcAuthorize) {
        try {
            if (!RESPONSE_TYPE_AVAILABLE.contains(oidcAuthorize.getResponse_type())) {
                return Result.setResult(HttpStatus.NOT_ACCEPTABLE, MessageCodeConfig.E00063,"", null, MessageCodeConfig.getErrorCode());
            }

            if (!verifyRedirectUri(oidcAuthorize.getClient_id(), oidcAuthorize.getRedirect_uri())) {
                return Result.setResult(HttpStatus.NOT_ACCEPTABLE, MessageCodeConfig.E00064,"", null, MessageCodeConfig.getErrorCode());
            }

            if (!StringUtils.hasText(oidcAuthorize.getState())) {
                oidcAuthorize.setState(UUID.randomUUID().toString().replaceAll("-", ""));
            }

            if (!StringUtils.hasText(oidcAuthorize.getScope())) {
                oidcAuthorize.setScope("openid profile");
            } else {
                String[] scopeList = oidcAuthorize.getScope().split("\\s+");
                for (String s : scopeList) {
                    if (SCOPE_AVAILABLE.contains(s)) {
                        return Result.setResult(HttpStatus.NOT_ACCEPTABLE, MessageCodeConfig.E00064,"", null, MessageCodeConfig.getErrorCode());
                    }
                }
            }

            // 重定向到登录页
            String loginPage = environment.getProperty("oidc.login.page");
            if ("register".equals(oidcAuthorize.getEntity())) {
                loginPage = environment.getProperty("oidc.register.page");
            }
            String loginPageRedirect = String.format("%s?client_id=%s&scope=%s&redirect_uri=%s&response_mode=query&state=%s",
                    loginPage,
                    oidcAuthorize.getClient_id(),
                    oidcAuthorize.getScope(),
                    oidcAuthorize.getRedirect_uri(),
                    oidcAuthorize.getState());

            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).header(HttpHeaders.LOCATION, loginPageRedirect).build();
        } catch (Exception e) {
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, MessageCodeConfig.E00012, "", null, MessageCodeConfig.getErrorCode());
        }
    }

    public boolean verifyRedirectUri(String clientId, String redirectUri) throws Exception {
        OneIdEntity.App app = oneIdAppDao.getAppInfo(clientId);
        String[] appRedirectUriList = app.getRedirectUrls().split(",");

        for (String s : appRedirectUriList) {
            if (s.contains("*")) {
                String patternString = s.replace("*", ".*");

                Pattern pattern = Pattern.compile(patternString);

                Matcher matcher = pattern.matcher(redirectUri);

                if (matcher.matches()) {
                    return true;
                }
            } else {
                if (s.equals(redirectUri)) {
                    return true;
                }
            }
        }

        return false;
    }
}
