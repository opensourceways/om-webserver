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
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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


public class HttpClientUtils implements Serializable {
    private static final Logger logger =  LoggerFactory.getLogger(HttpClientUtils.class);

    static PoolingHttpClientConnectionManager connectionManager;
    static ConnectionKeepAliveStrategy myStrategy;
    static CredentialsProvider credentialsProvider;
    static CloseableHttpClient client;

    static {
        credentialsProvider = new BasicCredentialsProvider();
    }

    public static CloseableHttpClient getClient() {
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

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
                logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            }
            res.put(domain, Boolean.valueOf(secure));
        }
        return res;
    }

    public static void setCookie(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse, String name, String value,
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
        if (domain == null) return;
        if (StringUtils.isBlank(path)) path = "/";

        Cookie cookie = new Cookie(name, value);
        cookie.setDomain(domain);
        cookie.setHttpOnly(isHttpOnly);
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAge);
        cookie.setPath(path);
        servletResponse.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletResponse servletResponse, String domainStr, String name, String path) {
        String[] domains = domainStr == null ? new String[]{} : domainStr.split(";");
        if (StringUtils.isBlank(path)) path = "/";

        for (String domain : domains) {
            Cookie cookie = new Cookie(name, "");
            cookie.setMaxAge(0);
            cookie.setPath(path);
            cookie.setDomain(domain);
            servletResponse.addCookie(cookie);
        }
    }

    public static Map<String, Object> getBodyFromRequest(HttpServletRequest request) {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> body = new HashMap<>();
        try {
            BufferedReader br = request.getReader();
            StringBuilder wholeStr = new StringBuilder();
            String str;
            while ((str = br.readLine()) != null) {
                wholeStr.append(str);
            }
            if (StringUtils.isNotBlank(wholeStr)) {
                body = objectMapper.convertValue(objectMapper.readTree(wholeStr.toString()),
                        new TypeReference<Map<String, Object>>() {
                        });
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return body;
    }
}
