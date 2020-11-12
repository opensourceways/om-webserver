package com.om.Utils;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import org.asynchttpclient.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

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
    public static SSLContext skipSsl() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance("SSL");

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
                return null;
            }
        };

        sc.init(null, new TrustManager[] { trustManager }, null);
        return sc;
    }


}