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

import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;


public class CodeUtil {
    // 华为云MSGSMS，用于格式化鉴权头域，给"Authorization"参数赋值
    public static final String AUTH_HEADER_VALUE = "WSSE realm=\"SDP\",profile=\"UsernameToken\",type=\"Appkey\"";

    // 华为云MSGSMS，用于格式化鉴权头域，给"X-WSSE"参数赋值
    private static final String WSSE_HEADER_FORMAT = "UsernameToken Username=\"%s\",PasswordDigest=\"%s\",Nonce=\"%s\",Created=\"%s\"";

    public String[] sendCode(String accountType, String account, JavaMailSender mailSender, Environment env) {
        String resMsg = "fail";
        long codeExpire = 60L;
        String code = null;
        try{
            // 生成验证码
            code = randomNumBuilder(Integer.parseInt(env.getProperty("code.length", "6")));

            switch (accountType.toLowerCase()) {
                case "email":
                    codeExpire = Long.parseLong(env.getProperty("mail.code.expire", "60"));
                    // 邮件服务器
                    String from = env.getProperty("spring.mail.username");
                    // 邮件信息
                    String[] info = buildEmailCodeInfo(account, code);
                    // 发送验证码
                    resMsg = sendSimpleMail(mailSender, from, account, info[0], info[1]);
                    break;
                case "phone":
                    codeExpire = Long.parseLong(env.getProperty("msgsms.code.expire", "60"));
                    // 短信发送服务器
                    String msgsms_app_key = env.getProperty("msgsms.app_key");
                    String msgsms_app_secret = env.getProperty("msgsms.app_secret");
                    String msgsms_url = env.getProperty("msgsms.url");
                    String msgsms_signature = env.getProperty("msgsms.signature");
                    String msgsms_sender = env.getProperty("msgsms.sender");
                    String msgsms_template_id = env.getProperty("msgsms.template.id");
                    // 短信发送请求
                    String templateParas = String.format("[\"%s\",\"%s\"]", code, env.getProperty("msgsms.template.context.expire", "1"));
                    String wsseHeader = buildWsseHeader(msgsms_app_key, msgsms_app_secret);
                    String body = buildSmsBody(msgsms_sender, account, msgsms_template_id, templateParas, "", msgsms_signature);
                    // 发送验证码
                    HttpResponse<JsonNode> response = Unirest.post(msgsms_url)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Authorization", CodeUtil.AUTH_HEADER_VALUE)
                            .header("X-WSSE", wsseHeader)
                            .body(body)
                            .asJson();
                    if (response.getStatus() == 200) resMsg = "send code success";
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new String[]{code, String.valueOf(codeExpire), resMsg};
    }

    /**
     * 发送简单的邮件
     *
     * @param mailSender 邮箱服务
     * @param from       发件邮箱
     * @param to         收件邮箱
     * @param title      标题
     * @param content    内容
     */
    public String sendSimpleMail(JavaMailSender mailSender, String from, String to, String title, String content) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject(title);
        message.setText(content);
        mailSender.send(message);
        return "send code success";
    }


    /**
     * 解除绑定邮箱，邮件信息
     *
     * @param email 邮箱
     * @param code  验证码
     * @return 邮件模板 {标题， 内容}
     */
    public String[] buildEmailUnbindInfo(String email, String code) {
        String title = "您正在解除绑定邮箱，验证码为：" + code;
        String content = "亲爱的用户：" + email + "\n\n" + title + ", 请保管好验证码。\n\n";
        return new String[]{title, content};
    }

    public String[] buildEmailCodeInfo(String email, String code) {
        String title = "您的验证码为：" + code;
        String content = "亲爱的用户：" + email + "\n\n" + title + ", 请保管好验证码。\n\n";
        return new String[]{title, content};
    }

    /**
     * 短信发送请求body
     *
     * @param sender         签名通道号(发送方)
     * @param receiver       接受号码，号码格式(包含国家码),示例:+8615123456789,多个号码之间用英文逗号分隔
     * @param templateId     模板ID
     * @param templateParas  模板内容
     * @param statusCallBack 选填,短信状态报告接收地址,推荐使用域名,为空或者不填表示不接收状态报告
     * @param signature      签名名称
     * @return
     */
    public String buildSmsBody(String sender, String receiver, String templateId, String templateParas,
                               String statusCallBack, String signature) {
        if (null == sender || null == receiver || null == templateId || sender.isEmpty() || receiver.isEmpty()
                || templateId.isEmpty()) {
            System.out.println("buildRequestBody(): sender, receiver or templateId is null.");
            return null;
        }
        HashMap<String, String> map = new HashMap<String, String>();

        map.put("from", sender);
        map.put("to", receiver);
        map.put("templateId", templateId);
        if (null != templateParas && !templateParas.isEmpty()) {
            map.put("templateParas", templateParas);
        }
        if (null != statusCallBack && !statusCallBack.isEmpty()) {
            map.put("statusCallback", statusCallBack);
        }
        if (null != signature && !signature.isEmpty()) {
            map.put("signature", signature);
        }

        StringBuilder sb = new StringBuilder();
        String temp = "";

        for (String s : map.keySet()) {
            try {
                temp = URLEncoder.encode(map.get(s), "UTF-8");
            } catch (Exception e) {
                e.printStackTrace();
            }
            sb.append(s).append("=").append(temp).append("&");
        }

        return sb.deleteCharAt(sb.length() - 1).toString();
    }

    /**
     * 短信发送请求header
     *
     * @param appKey    APP_Key
     * @param appSecret APP_Secret
     * @return
     */
    public String buildWsseHeader(String appKey, String appSecret) {
        if (null == appKey || null == appSecret || appKey.isEmpty() || appSecret.isEmpty()) {
            System.out.println("buildWsseHeader(): appKey or appSecret is null.");
            return null;
        }
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        String time = sdf.format(new Date()); //Created
        String nonce = UUID.randomUUID().toString().replace("-", ""); //Nonce

        MessageDigest md;
        byte[] passwordDigest = null;

        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update((nonce + time + appSecret).getBytes());
            passwordDigest = md.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        // PasswordDigest
        String passwordDigestBase64Str = Base64.getEncoder().encodeToString(passwordDigest);

        return String.format(WSSE_HEADER_FORMAT, appKey, passwordDigestBase64Str, nonce, time);
    }

    /**
     * 随机生成验证码
     *
     * @return 验证码
     */
    public String randomNumBuilder(int codeLength) throws NoSuchAlgorithmException {
        StringBuilder result = new StringBuilder();
        SecureRandom instance = SecureRandom.getInstanceStrong();
        for (int i = 0; i < codeLength; i++) {
            result.append(instance.nextInt(9));
        }
        return result.toString();
    }

    /**
     * 随机生成字符串
     * @param strLength 字符串长度
     * @return 随机字符串
     */
    public String randomStrBuilder(int strLength) throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        return new BigInteger(160, random).toString(strLength);
    }
}
