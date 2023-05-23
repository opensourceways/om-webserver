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

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Result.Constant;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import javax.mail.internet.MimeMessage;
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


public class CodeUtil {
    // 华为云MSGSMS，用于格式化鉴权头域，给"Authorization"参数赋值
    public static final String AUTH_HEADER_VALUE = "WSSE realm=\"SDP\",profile=\"UsernameToken\",type=\"Appkey\"";

    // 华为云MSGSMS，用于格式化鉴权头域，给"X-WSSE"参数赋值
    private static final String WSSE_HEADER_FORMAT = "UsernameToken Username=\"%s\",PasswordDigest=\"%s\",Nonce=\"%s\",Created=\"%s\"";

    public String[] sendCode(String accountType, String account, JavaMailSender mailSender, Environment env, String community) {
        String resMsg = "fail";
        long codeExpire = 60L;
        String code = null;
        try {
            // 生成验证码
            code = randomNumBuilder(Integer.parseInt(env.getProperty("code.length", Constant.DEFAULT_CODE_LENGTH)));

            switch (accountType.toLowerCase()) {
                case "email":
                    codeExpire = Long.parseLong(env.getProperty("mail.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
                    // 邮件服务器
                    String from = env.getProperty("spring.mail.username");
                    // 邮件信息
                    String[] info = buildEmailCodeInfo(account, code,
                            env.getProperty("mail.template.expire.minutes", Constant.DEFAULT_EXPIRE_MINUTE));
                    // 发送验证码
                    resMsg = sendHtmlMail(mailSender, from, account, info[0], info[1]);
                    break;
                case "phone":
                    codeExpire = Long.parseLong(env.getProperty("msgsms.code.expire", Constant.DEFAULT_EXPIRE_SECOND));
                    // 短信发送服务器
                    String communityTemp = StringUtils.isBlank(community) ? "" : community + ".";
                    String msgsms_app_key = env.getProperty(communityTemp + "msgsms.app_key");
                    String msgsms_app_secret = env.getProperty(communityTemp + "msgsms.app_secret");
                    String msgsms_url = env.getProperty(communityTemp + "msgsms.url");
                    String msgsms_signature = env.getProperty(communityTemp + "msgsms.signature");
                    String msgsms_sender = env.getProperty(communityTemp + "msgsms.sender");
                    String msgsms_template_id = env.getProperty(communityTemp + "msgsms.template.id");
                    // 短信发送模板赋值
                    String templateParas = (community.equalsIgnoreCase("opengauss"))
                            ? String.format("[\"%s\",\"%s\"]", code, env.getProperty("msgsms.template.expire.minutes"))
                            : String.format("[\"%s\"]", code);
                    String wsseHeader = buildWsseHeader(msgsms_app_key, msgsms_app_secret);
                    String body = buildSmsBody(msgsms_sender, account, msgsms_template_id,
                            templateParas, "", msgsms_signature);
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
     * 发送html邮件
     *
     * @param mailSender 邮箱服务
     * @param from       发件邮箱
     * @param to         收件邮箱
     * @param title      标题
     * @param content    html格式的内容
     */
    public String sendHtmlMail(JavaMailSender mailSender, String from, String to, String title, String content) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper messageHelper = new MimeMessageHelper(message);
            String format = String.format("Open Source Community<%s>", from); // 发件人名称<发件人邮箱>
            messageHelper.setFrom(format);
            messageHelper.setTo(to);
            messageHelper.setSubject(title);
            messageHelper.setText(content, true);
            mailSender.send(message);
            return "send code success";
        } catch (Exception e) {
            return "send code fail";
        }
    }

    /**
     * 解除绑定邮箱，邮件信息
     *
     * @param email 邮箱
     * @param code  验证码
     * @return 邮件模板 {标题， 内容}
     */
    public String[] buildEmailCodeInfo(String email, String code, String expireMinutes) {
        String title = "Verification of Community User";

        // 构造模板引擎
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        TemplateEngine templateEngine = new TemplateEngine();
        templateEngine.setTemplateResolver(resolver);

        // 注入变量值
        Context context = new Context();
        context.setVariable("email", email);
        context.setVariable("code", code);
        context.setVariable("expire", expireMinutes);

        String emailContent = templateEngine.process("emailTemplate", context);
        return new String[]{title, emailContent};
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
     *
     * @param strLength 字符串长度
     * @return 随机字符串
     */
    public String randomStrBuilder(int strLength) throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        return new BigInteger(160, random).toString(strLength);
    }
}
