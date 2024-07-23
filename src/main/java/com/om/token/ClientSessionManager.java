package com.om.token;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 类描述：通用清除第三方接入的cookie.
 */
@Component
public class ClientSessionManager {
    /**
     * 需要额外清除的cookie名.
     */
    @Value("${thirdParty.client.session.name:}")
    private  String clearCookie;

    /**
     * 要清除的cookie的域.
     * @param csrfDomain
     */
    @Value("${thirdParty.client.session.domain:}")
    private  String clearDomain;

    /**
     * 删除cookie基本方法.
     * @param servletResponse HTTP响应
     * @param name cookie名
     * @param domain cookie域
     */
    private static void deleteCookie(HttpServletResponse servletResponse, String name, String domain) {
        Cookie cookie = new Cookie(name, "");
        cookie.setMaxAge(0);
        cookie.setPath("/");
        if (StringUtils.isNotEmpty(domain)) {
            cookie.setDomain(domain);
        }
        servletResponse.addCookie(cookie);
    }

    /**
     * 删除配置文件里配置的cookie.
     *
     * @param servletResponse HTTP响应对象
     */
    public void deleteCookieInConfig(HttpServletResponse servletResponse) {
        if (StringUtils.isEmpty(clearCookie)) {
            return;
        }
        String[] cookieNames = clearCookie.split(";");
        String[] cookieDomains = clearDomain.split(";");
        for (String cookieName : cookieNames) {
            for (String cookieDomain : cookieDomains) {
                deleteCookie(servletResponse, cookieName, cookieDomain);
            }
            deleteCookie(servletResponse, cookieName, null);
        }
    }



}
