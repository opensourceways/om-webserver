/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.service;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.UUID;
import java.util.Map;
import java.util.Arrays;
import java.util.Base64;
import java.util.TimeZone;

@Component
public class SendMessageService {

    /**
     * 云短信.
     */
    @Value("${tianyiyun.message.url:}")
    private String sendMessageUrl;

    /**
     * 云短信.
     */
    @Value("${tianyiyun.access.key:}")
    private String accessKey;

    /**
     * 云短信.
     */
    @Value("${tianyiyun.security.key:}")
    private String securityKey;

    /**
     * 云短信.
     */
    @Value("${tianyiyun.template.id:}")
    private String templateId;


    /**
     * 日志记录器，用于记录身份验证拦截器的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SendMessageService.class);

    /**
     * 发送短信.
     *
     * @param map
     * @param servletRequest
     * @return 短信返回体
     * @throws Exception
     */
    public Object getMessage(String map, HttpServletRequest servletRequest) throws Exception {
        if (StringUtils.isEmpty(sendMessageUrl)) {
            LOGGER.error("sendMessage Error, sendMessageUrl is not found");
            return "";
        }
        Map<String, String> infoMap = new HashMap<>();
        String[] item = map.split("&");
        for (String it : item) {
            if (it.split("=").length == 2) {
                infoMap.put(it.split("=")[0], it.split("=")[1]);
            }
        }
        String wsse  = servletRequest.getHeader("x-wsse");
        String accessKey = "";
        String[] wsses = wsse.split(",");
        for (String wss : wsses) {
            if (wss.startsWith("UsernameToken Username=")) {
                accessKey = wss.replace("UsernameToken Username=", "")
                        .replace("\"", "");
                break;
            }
        }
        String phone = infoMap.get("to");
        String templateCode = infoMap.get("templateId");
        String signName = infoMap.get("signature");
        String securityKey = infoMap.get("from");
        String content = infoMap.get("templateParas");
        content = URLDecoder.decode(URLDecoder.decode(content, StandardCharsets.UTF_8), StandardCharsets.UTF_8)
                .replace("[", "")
                .replace("]", "");
        // 参数判空
        if (StringUtils.isEmpty(accessKey) || StringUtils.isEmpty(securityKey) || StringUtils.isEmpty(templateCode)
                || StringUtils.isEmpty(signName) || StringUtils.isEmpty(phone)  || StringUtils.isEmpty(content)) {
            LOGGER.error("sendMessage Error, input is empty");
            return "";
        }
        // 重要参数校验
        if (!accessKey.equals(this.accessKey) || !securityKey.equals(this.securityKey)
                || !templateCode.equals(templateId)) {
            LOGGER.error("sendMessage Error, input is invalid");
            return "";
        }
        return sendMessage(phone, signName, templateId, this.accessKey, this.securityKey, content);
    }

    private Object sendMessage(String phoneNumber, String signName, String templateCode,
                               String accessKey, String securityKey, String content) throws Exception {
        URL url = new URL(sendMessageUrl);
        // 请求body.
        String body = getBodyInfo(phoneNumber, signName, templateCode, content);
        // 构造时间戳
        SimpleDateFormat timeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        Date nowdate = new Date();
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8:00"));
        timeFormat.setTimeZone(TimeZone.getTimeZone("GMT+8:00"));
        String singerDate = timeFormat.format(nowdate);
        String singerDd = dateFormat.format(nowdate);
        // 构造请求流水号
        String uuId = UUID.randomUUID().toString();
        // 构造签名
        String sigtureStr = getSigtureStr(body, singerDate, uuId, url);
        String signature = getSignature(accessKey, securityKey, singerDate, singerDd, sigtureStr);
        // 构造请求头
        HttpPost httpPost = getHttpPost(accessKey, singerDate, uuId, url, signature);
        // 构造请求体
        httpPost.setEntity(new StringEntity(body, ContentType.create("application/json", "utf-8")));
        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(httpPost)) {
            String s = EntityUtils.toString(response.getEntity(), "utf-8");
            JSONObject js = (JSONObject) JSON.parse(s);
            if ("OK".equals(js.getString("code")) && "success".equals(js.getString("message"))) {
                return getJsonObject(phoneNumber, singerDate, js);
            } else {
                LOGGER.error("发送短信失败{}", s);
            }
            return JSON.parse(s);
        } catch (Exception e) {
            LOGGER.error("sendMessage Error {}", e.getMessage());
        }
        return "";
    }

    @NotNull
    private JSONObject getJsonObject(String phoneNumber, String singerDate, JSONObject js) {
        JSONObject res = new JSONObject();
        JSONArray ja = new JSONArray();
        JSONObject j = new JSONObject();
        j.put("orginTo", phoneNumber);
        j.put("createTime", singerDate);
        j.put("from", "");
        j.put("smsMsgId", js.get("requestId"));
        j.put("status", "000000");
        j.put("countryId", "CN");
        j.put("total", 1);
        ja.add(j);
        res.put("result", ja);
        res.put("code", "000000");
        res.put("description", "Success");
        return res;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        byte[] var2 = data;
        int var3 = data.length;
        for (int var4 = 0; var4 < var3; ++var4) {
            byte b = var2[var4];
            String hex = Integer.toHexString(b);
            if (hex.length() == 1) {
                sb.append("0");
            } else if (hex.length() == 8) {
                hex = hex.substring(6);
            }
            sb.append(hex);
        }
        return sb.toString().toLowerCase(Locale.getDefault());
    }

    private static String getSHA256(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(text.getBytes(StandardCharsets.UTF_8));
            return toHex(md.digest());
        } catch (NoSuchAlgorithmException var3) {
            return null;
        }
    }

    private static byte[] hmacsha256(byte[] data, byte[] key) throws Exception {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    private String getBodyInfo(String phoneNumber, String signName, String templateCode, String content) {
        Map<String, Object> params = new HashMap<>();
        params.put("action", "SendSms");
        //在控制台上申请并通过的短信签名。
        params.put("signName", signName);
        //接收短信的目标手机号，多个手机号使用英文逗号分开
        params.put("phoneNumber", phoneNumber);
        //在控制台上申请并通过的短信模板，此模板为测试专用模板，可直接进行测试
        params.put("templateCode", templateCode);
        //短信模板对应的模板参数和值。此值为测试模板的变量及参数，可直接使用
        String contentStr =  "{\"a\":\\" + content + "\\}";
        params.put("templateParam", contentStr);
        params.put("extendCode", "");
        params.put("sessionId", "");
        return JSONObject.toJSONString(params);
    }

    private String getSigtureStr(String body, String singerDate, String uuId, URL url) {
        String campmocalHeader = "ctyun-eop-request-id:" + uuId + "\neop-date:" + singerDate + "\n";
        // header的key按照26字母进行排序, 以&作为连接符连起来
        String query = url.getQuery();
        String afterQuery = "";
        if (query != null) {
            String[] param = query.split("&");
            Arrays.sort(param);
            for (String str : param) {
                if (afterQuery.length() < 1) {
                    afterQuery = afterQuery + str;
                } else {
                    afterQuery = afterQuery + "&" + str;
                }
            }
        }
        String calculateContentHash = getSHA256(body); // 报文原封不动进行sha256摘要
        return campmocalHeader + "\n" + afterQuery + "\n" + calculateContentHash;
    }

    private String getSignature(String accessKey, String securityKey, String singerDate,
                                String singerDd, String sigtureStr) throws Exception {
        byte[] ktime = hmacsha256(singerDate.getBytes(StandardCharsets.UTF_8),
                securityKey.getBytes(StandardCharsets.UTF_8));
        byte[] kAk = hmacsha256(accessKey.getBytes(StandardCharsets.UTF_8), ktime);
        byte[] kdate = hmacsha256(singerDd.getBytes(StandardCharsets.UTF_8), kAk);
        return Base64.getEncoder().encodeToString(hmacsha256(sigtureStr.getBytes(StandardCharsets.UTF_8), kdate));
    }


    private HttpPost getHttpPost(String accessKey, String singerDate, String uuId, URL url, String Signature) {
        HttpPost httpPost = new HttpPost(String.valueOf(url));
        httpPost.setHeader("Content-Type", "application/json;charset=UTF-8");
        httpPost.setHeader("ctyun-eop-request-id", uuId);
        httpPost.setHeader("Eop-date", singerDate);
        String signHeader = String.format("%s Headers=ctyun-eop-request-id;eop-date Signature=%s", accessKey,
                Signature);
        httpPost.setHeader("Eop-Authorization", signHeader);
        return httpPost;
    }

}
