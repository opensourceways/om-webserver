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

import java.io.Serializable;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HeaderElement;
import org.apache.http.HeaderElementIterator;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeaderElementIterator;
import org.apache.http.protocol.HTTP;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;


public class HttpClientUtils implements Serializable {
    static PoolingHttpClientConnectionManager connectionManager;
    static ConnectionKeepAliveStrategy myStrategy;
    static CredentialsProvider credentialsProvider;
    static CloseableHttpClient client;

    static {
        SSLContext sslcontext = null;
        try {
            sslcontext = skipSsl();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        //设置协议http和https对应的处理socket链接工厂的对象
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.INSTANCE)
                .register("https", new SSLConnectionSocketFactory(sslcontext))
                .build();
        connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        connectionManager.setMaxTotal(1000);
        connectionManager.setDefaultMaxPerRoute(50);
        myStrategy = (response, context) -> {
            HeaderElementIterator it = new BasicHeaderElementIterator
                    (response.headerIterator(HTTP.CONN_KEEP_ALIVE));
            while (it.hasNext()) {
                HeaderElement he = it.nextElement();
                String param = he.getName();
                String value = he.getValue();
                if (value != null && param.equalsIgnoreCase
                        ("timeout")) {
                    return Long.parseLong(value) * 1000;
                }
            }
            return 60 * 1000;//如果没有约定，则默认定义时长为60s
        };


        credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials("admin", "Cloudfoundry@123"));
    }

    public static CloseableHttpClient getClient() {
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    public static SSLContext skipSsl() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance("SSL");

        // 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法
        X509TrustManager trustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(
                    java.security.cert.X509Certificate[] paramArrayOfX509Certificate,
                    String paramString) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(
                    java.security.cert.X509Certificate[] paramArrayOfX509Certificate,
                    String paramString) throws CertificateException {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };

        sc.init(null, new TrustManager[]{trustManager}, null);
        return sc;
    }

    public static RestHighLevelClient restClient(String host, int port, String scheme, String user, String password) {
        RestHighLevelClient client = null;
        try {
            BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(user, password));

            RestClientBuilder builder = RestClient.builder(new HttpHost(host, port, scheme));

            builder.setHttpClientConfigCallback(httpAsyncClientBuilder -> {
                httpAsyncClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                SSLContext sc = null;
                try {
                    sc = skipSsl();
                } catch (NoSuchAlgorithmException | KeyManagementException e) {
                    e.printStackTrace();
                }
                return httpAsyncClientBuilder.setSSLContext(sc);
            });
            builder.setRequestConfigCallback(requestConfigBuilder -> {
                requestConfigBuilder.setConnectTimeout(5000);
                requestConfigBuilder.setSocketTimeout(60000);
                return requestConfigBuilder;
            });

            client = new RestHighLevelClient(builder);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return client;
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
                e.printStackTrace();
            }
            res.put(domain, Boolean.valueOf(secure));
        }
        return res;
    }

    public static void setCookie(String serverName, String referer, HttpServletResponse servletResponse, String name, String value,
                                 boolean isHttpOnly, int maxAge, String path, HashMap<String, Boolean> domain2Secure) {
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

    public static void setCookie(HttpServletRequest httpServletRequest, HttpServletResponse servletResponse, String name, String value,
                                 boolean isHttpOnly, int maxAge, String path, HashMap<String, Boolean> domain2Secure) {
        String serverName = httpServletRequest.getServerName();
        String referer = httpServletRequest.getHeader("referer");
        setCookie(serverName, referer, servletResponse, name, value, isHttpOnly, maxAge, path, domain2Secure);
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
}
