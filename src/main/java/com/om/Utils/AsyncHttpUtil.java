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

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import javax.net.ssl.*;
import org.asynchttpclient.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;


@Service
public class AsyncHttpUtil {
    @Value("${userpass}")
    String user_pass;
    static volatile AsyncHttpClient asyncHttpClient=null;

    public static synchronized   AsyncHttpClient getClient() throws KeyManagementException, NoSuchAlgorithmException {
        if (asyncHttpClient==null){
            asyncHttpClient = new DefaultAsyncHttpClient(new DefaultAsyncHttpClientConfig.Builder()
                    .setConnectTimeout(100000)
                    .setRequestTimeout(100000).setSslContext(new JdkSslContext(skipSsl(),true, ClientAuth.NONE))
                    .build());
        }

        return asyncHttpClient;
    }
    public  RequestBuilder getBuilder(){
    RequestBuilder builder=new RequestBuilder();
    builder.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
    builder.addHeader("Authorization", "Basic "+Base64.getEncoder().encodeToString((user_pass).getBytes()))
    .setMethod("POST");
    return builder;

}
public  static Response getHTML(String url, String method, Map header) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException {
    Request build = new RequestBuilder().setMethod(method).setUrl(url).setHeaders(header).build();
    ListenableFuture<Response> responseListenableFuture = getClient().executeRequest(build);
    Response response = responseListenableFuture.get();
    return response;
}
    public static SSLContext skipSsl() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance("TLSv1.2");

        // 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法
        X509TrustManager trustManager = new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {

            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {

            }

            @Override
            public void checkClientTrusted(
                    X509Certificate[] paramArrayOfX509Certificate,
                    String paramString) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(
                    X509Certificate[] paramArrayOfX509Certificate,
                    String paramString) throws CertificateException {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        SecureRandom secureRandom = SecureRandom.getInstance("NativePRNGBlocking");
        sc.init(null, new TrustManager[] { trustManager }, secureRandom);
        return sc;
    }


}