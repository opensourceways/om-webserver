package com.om.Utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public final class ManageCookieUtil {
    /**
     * 清理cookie配置项.
     */
    private static String clearCookie;

    /**
     * 清理cookie配置域.
     */
    private static String domain;

    /**
     * openMind平台需要额外清除的cookie.
     * @param csrfName
     */
    @Value("${openmind.cookie.csrftoken.name:}")
    private void setName(String csrfName) {
        setCsrfName(csrfName);
    }

    /**
     * 要清除的cookie名.
     * @param csrfDomain
     */
    @Value("${openmind.cookie.csrftoken.domain:}")
    private void setDomain(String csrfDomain) {
        setCsrfDomain(csrfDomain);
    }

    /**
     * 清除cookie的name赋值.
     * @param name
     */
    private static void setCsrfName(String name) {
        ManageCookieUtil.clearCookie = name;
    }

    /**
     * 清除cookie的域赋值.
     * @param domain
     */
    private static void setCsrfDomain(String domain) {
        ManageCookieUtil.domain = domain;
    }

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
     * 删除openMind的csrf_token与sessionId.
     *
     * @param servletResponse HTTP响应对象
     */
    public static void deleteCsrfCookieOnOpenMind(HttpServletResponse servletResponse) {
        if (StringUtils.isEmpty(clearCookie)) {
            return;
        }
        String[] cookieNames = clearCookie.split(";");
        if (cookieNames.length < 2) {
            return;
        }
        deleteCookie(servletResponse, cookieNames[0], domain);
        deleteCookie(servletResponse, cookieNames[1], domain);
        deleteCookie(servletResponse, cookieNames[1], null);
    }

}
