package com.om.utils.thirdauthorizationurl;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Component
public class GiteeAuthorizationUrlUtil {
    /**
     * Gitee 企业登录的标识符.
     */
    @Value("${enterprise.identifier.gitee}")
    private String enterIdentifieGitee;

    /**
     * Gitee 企业登录的授权 URL.
     */
    @Value("${enterprise.authorizationUrl.gitee: }")
    private String enterAuthUrlGitee;

    /**
     * Gitee 社会登录的授权 URL.
     */
    @Value("${social.authorizationUrl.gitee: }")
    private String socialAuthUrlGitee;

    /**
     * 配置企业源gitee url或者社会源gitee url.
     * @param appId appId.
     * @param userToken 用户token.
     * @return gitee授权url.
     */
    public HashMap<String, String> generateAuthorizationUrl(String appId, String userToken) {
        if (StringUtils.isNotBlank(enterAuthUrlGitee)) {
           return enterAuth(appId, userToken);
        } else if (StringUtils.isNotBlank(enterIdentifieGitee)) {
            return socialAuth(appId, userToken);
        }
        return null;
    }

    private HashMap<String, String> socialAuth(String appId, String userToken) {
        HashMap<String, String> mapGitee = new HashMap<>();
        String authGitee = String.format(socialAuthUrlGitee, enterIdentifieGitee, appId, userToken);
        mapGitee.put("name", "enterprise_gitee");
        mapGitee.put("authorizationUrl", authGitee);
        return mapGitee;
    }

    private HashMap<String, String> enterAuth(String appId, String userToken) {
        HashMap<String, String> mapGitee = new HashMap<>();
        String authGitee = String.format(enterAuthUrlGitee, appId, enterIdentifieGitee, userToken);
        mapGitee.put("name", "enterprise_gitee");
        mapGitee.put("authorizationUrl", authGitee);
        return mapGitee;
    }
}
