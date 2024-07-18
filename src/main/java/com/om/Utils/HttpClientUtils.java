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

package com.om.Utils;

import java.io.BufferedReader;
import java.io.Serializable;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.MessageCodeConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public final class HttpClientUtils implements Serializable {
    private HttpClientUtils() {
        throw new AssertionError("Utility class. Not intended for instantiation.");
    }

    /**
     * 日志记录器实例，用于记录 HttpClientUtils 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientUtils.class);

    /**
     * 静态连接池管理器.
     */
    private static PoolingHttpClientConnectionManager connectionManager;

    /**
     * 自定义连接保持策略.
     */
    private static ConnectionKeepAliveStrategy myStrategy;

    /**
     * 凭据提供者.
     */
    private static CredentialsProvider credentialsProvider = new BasicCredentialsProvider();

    /**
     * 可关闭的 HTTP 客户端.
     */
    private static CloseableHttpClient client;

    /**
     * 获取可关闭的 HTTP 客户端实例.
     *
     * @return CloseableHttpClient 对象
     */
    public static CloseableHttpClient getClient() {
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    /**
     * 获取配置的 Cookie 信息并存储在HashMap中.
     *
     * @param domainsStr 域名字符串
     * @param securesStr 安全性字符串
     * @return 包含配置的 Cookie 信息的 HashMap
     */
    public static HashMap<String, Boolean> getConfigCookieInfo(String domainsStr, String securesStr) {
        HashMap<String, Boolean> res = new HashMap<>();
        String[] domains = domainsStr.split(";");
        String[] secures = securesStr.split(";");

        for (int i = 0; i < domains.length; i++) {
            String domain = domains[i];
            String secure = "true";
            try {
                secure = secures[i];
            } catch (Exception e) {
                LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            }
            res.put(domain, Boolean.valueOf(secure));
        }
        return res;
    }

    /**
     * 设置 Cookie 到 HttpServletResponse.
     *
     * @param httpServletRequest HTTP请求对象
     * @param servletResponse    HTTP响应对象
     * @param name               Cookie名称
     * @param value              Cookie值
     * @param isHttpOnly         是否是 HttpOnly
     * @param maxAge             最大年龄
     * @param path               路径
     * @param domain2Secure      域名到安全性的映射
     */
    public static void setCookie(HttpServletRequest httpServletRequest,
                                 HttpServletResponse servletResponse, String name, String value,
                                 boolean isHttpOnly, int maxAge, String path, HashMap<String, Boolean> domain2Secure) {
        String serverName = httpServletRequest.getServerName();
        String referer = httpServletRequest.getHeader("referer");
        if (StringUtils.isNotBlank(referer)) {
            int fromIndex;
            int endIndex;
            if (referer.startsWith("http://")) {
                fromIndex = 7;
                endIndex = referer.indexOf(":", fromIndex);
            } else {
                fromIndex = 8;
                endIndex = referer.indexOf("/", fromIndex);
                endIndex = endIndex == -1 ? referer.length() : endIndex;
            }
            serverName = referer.substring(0, endIndex);
        }

        String domain = null;
        boolean secure = true;
        for (Map.Entry<String, Boolean> entry : domain2Secure.entrySet()) {
            String key = entry.getKey();
            if (serverName.endsWith(key)) {
                domain = entry.getKey();
                secure = entry.getValue();
                break;
            }
        }
        if (domain == null) {
            return;
        }
        if (StringUtils.isBlank(path)) {
            path = "/";
        }

        Cookie cookie = new Cookie(name, value);
        cookie.setDomain(domain);
        cookie.setHttpOnly(isHttpOnly);
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAge);
        cookie.setPath(path);
        servletResponse.addCookie(cookie);
    }

    /**
     * 删除指定域名和路径下的 Cookie.
     *
     * @param servletResponse HTTP响应对象
     * @param domainStr       域名字符串
     * @param name            Cookie名称
     * @param path            路径
     */
    public static void deleteCookie(HttpServletResponse servletResponse, String domainStr, String name, String path) {
        String[] domains = domainStr == null ? new String[]{} : domainStr.split(";");
        if (StringUtils.isBlank(path)) {
            path = "/";
        }

        for (String domain : domains) {
            Cookie cookie = new Cookie(name, "");
            cookie.setMaxAge(0);
            cookie.setPath(path);
            cookie.setDomain(domain);
            servletResponse.addCookie(cookie);
        }
    }

    /**
     * 从HttpServletRequest中获取请求体内容并转为Map对象.
     *
     * @param request HTTP请求对象
     * @return 包含请求体内容的 Map 对象
     */
    public static Map<String, Object> getBodyFromRequest(HttpServletRequest request) {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> body = new HashMap<>();
        try (BufferedReader br = request.getReader()) {
            StringBuilder wholeStr = new StringBuilder();
            String str;
            while ((str = br.readLine()) != null) {
                wholeStr.append(str);
            }
            if (StringUtils.isNotBlank(wholeStr)) {
                body = objectMapper.convertValue(objectMapper.readTree(wholeStr.toString()),
                        new TypeReference<Map<String, Object>>() {
                        });
                String[] idKeyList = {"username"};
                List<String> idKey = Arrays.asList(idKeyList);
                for (Map.Entry<String, Object> entry : body.entrySet()) {
                    if (idKey.contains(entry.getKey())) {
                        request.setAttribute(entry.getKey(), entry.getValue());
                        break;
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return body;
    }

    /** 获取去掉顶级域名的子域名及本域名数组.
     *
     * @param urlString
     * @return 包含去掉顶级域名的子域名及本域名数组
     */
    public static List<String> extractSubdomains(String urlString) {
        try {
            URL url = new URL(urlString);
            String host = url.getHost();
            // 分割主机名以获取子域名部分
            String[] parts = host.split("\\.");
            // 如果只有一个部分（例如 localhost），则不进行处理
            if (parts.length <= 1) {
                return new ArrayList<>();
            }
            // 重建子域名列表，从TLD开始
            List<String> subdomains = new ArrayList<>();
            StringBuilder sb = new StringBuilder();
            for (int i = parts.length - 1; i > 0; i--) { // 跳过TLD
                sb.insert(0, parts[i] + ".");
                subdomains.add(sb.toString().substring(0, sb.length() - 1)); // 去掉开头的点
            }
            // 添加完整的主机名
            subdomains.add(host);
            // 去掉顶级域名
            subdomains.remove(0);
            return subdomains;

        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
}
