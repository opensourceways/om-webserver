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

package com.om.utils;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import com.om.modules.MessageCodeConfig;
import com.om.result.Constant;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import jakarta.mail.internet.MimeMessage;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.DrbgParameters.Capability;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class CodeUtil {
    /**
     * 日志记录器，用于记录 CodeUtil 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CodeUtil.class);

    /**
     * 华为云MSGSMS，用于格式化鉴权头域，给"Authorization"参数赋值.
     */
    public static final String AUTH_HEADER_VALUE = "WSSE realm=\"SDP\",profile=\"UsernameToken\",type=\"Appkey\"";

    /**
     * 华为云MSGSMS，用于格式化鉴权头域，给"X-WSSE"参数赋值.
     */
    private static final String WSSE_HEADER_FORMAT =
            "UsernameToken Username=\"%s\",PasswordDigest=\"%s\",Nonce=\"%s\",Created=\"%s\"";

    /**
     * 随机字符串生成源.
     */
    private static final String DATA_FOR_RANDOM_STRING = "abcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * 发送验证码并返回字符串数组.
     *
     * @param accountType 账户类型
     * @param account     账户信息
     * @param mailSender  JavaMailSender 对象
     * @param env         环境对象
     * @param community   社区信息
     * @return 字符串数组
     */
    public String[] sendCode(String accountType, String account,
                             JavaMailSender mailSender, Environment env, String community) {
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
                    String msgsmsAppKey = env.getProperty(communityTemp + "msgsms.app_key");
                    String msgsmsAppSecret = env.getProperty(communityTemp + "msgsms.app_secret");
                    String msgsmsUrl = env.getProperty(communityTemp + "msgsms.url");
                    String msgsmsSignature = env.getProperty(communityTemp + "msgsms.signature");
                    String msgsmsSender = env.getProperty(communityTemp + "msgsms.sender");
                    String msgsmsTemplateId = env.getProperty(communityTemp + "msgsms.template.id");
                    // 短信发送模板赋值
                    String templateParas = (community.equalsIgnoreCase("opengauss"))
                            ? String.format("[\"%s\",\"%s\"]", code, env.getProperty("msgsms.template.expire.minutes"))
                            : String.format("[\"%s\"]", code);
                    String wsseHeader = buildWsseHeader(msgsmsAppKey, msgsmsAppSecret);
                    String body = buildSmsBody(msgsmsSender, account, msgsmsTemplateId,
                            templateParas, "", msgsmsSignature);
                    // 发送验证码
                    HttpResponse<JsonNode> response = Unirest.post(msgsmsUrl)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Authorization", CodeUtil.AUTH_HEADER_VALUE)
                            .header("X-WSSE", wsseHeader)
                            .body(body)
                            .asJson();
                    if (response.getStatus() == 200) {
                        resMsg = "send code success";
                    }
                    break;
                default:
                    break;
            }
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException" + e.getMessage());
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }
        return new String[]{code, String.valueOf(codeExpire), resMsg};
    }

    /**
     * 发送html邮件.
     *
     * @param mailSender 邮箱服务
     * @param from       发件邮箱
     * @param to         收件邮箱
     * @param title      标题
     * @param content    html格式的内容
     * @return 发送邮件结果
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
     * 解除绑定邮箱，邮件信息.
     *
     * @param email         邮箱
     * @param code          验证码
     * @param expireMinutes 过期分钟数
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
     * 短信发送请求body.
     *
     * @param sender         签名通道号(发送方)
     * @param receiver       接受号码，号码格式(包含国家码),示例:+8615123456789,多个号码之间用英文逗号分隔
     * @param templateId     模板ID
     * @param templateParas  模板内容
     * @param statusCallBack 选填,短信状态报告接收地址,推荐使用域名,为空或者不填表示不接收状态报告
     * @param signature      签名名称
     * @return 构建的短信内容字符串
     */
    public String buildSmsBody(String sender, String receiver, String templateId, String templateParas,
                               String statusCallBack, String signature) {
        if (sender == null || receiver == null || templateId == null || sender.isEmpty() || receiver.isEmpty()
                || templateId.isEmpty()) {
            LOGGER.error("buildRequestBody(): sender, receiver or templateId is null.");
            return null;
        }
        HashMap<String, String> map = new HashMap<String, String>();

        map.put("from", sender);
        map.put("to", receiver);
        map.put("templateId", templateId);
        if (templateParas != null && !templateParas.isEmpty()) {
            map.put("templateParas", templateParas);
        }
        if (statusCallBack != null && !statusCallBack.isEmpty()) {
            map.put("statusCallback", statusCallBack);
        }
        if (signature != null && !signature.isEmpty()) {
            map.put("signature", signature);
        }

        StringBuilder sb = new StringBuilder();
        String temp = "";

        for (Map.Entry<String, String> entry : map.entrySet()) {
            String s = entry.getKey();
            try {
                temp = URLEncoder.encode(map.get(s), "UTF-8");
            } catch (Exception e) {
                LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            }
            sb.append(s).append("=").append(temp).append("&");
        }

        return sb.deleteCharAt(sb.length() - 1).toString();
    }

    /**
     * 短信发送请求header.
     *
     * @param appKey    APP_Key
     * @param appSecret APP_Secret
     * @return 短信发送请求header
     */
    public String buildWsseHeader(String appKey, String appSecret) throws NoSuchAlgorithmException {
        if (appKey == null || appSecret == null || appKey.isEmpty() || appSecret.isEmpty()) {
            LOGGER.error("buildWsseHeader(): appKey or appSecret is null.");
            return null;
        }
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        String time = sdf.format(new Date()); //Created
        String nonce = randomStrBuilder(Constant.RANDOM_DEFAULT_LENGTH); //Nonce

        MessageDigest md;
        byte[] passwordDigest = null;

        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update((nonce + time + appSecret).getBytes(StandardCharsets.UTF_8));
            passwordDigest = md.digest();
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
        }

        // PasswordDigest
        String passwordDigestBase64Str = Base64.getEncoder().encodeToString(passwordDigest);

        return String.format(WSSE_HEADER_FORMAT, appKey, passwordDigestBase64Str, nonce, time);
    }

    /**
     * 随机生成验证码.
     *
     * @param codeLength 随机数长度
     * @return 生成的随机数字字符串
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     */
    public String randomNumBuilder(int codeLength) throws NoSuchAlgorithmException {
        StringBuilder result = new StringBuilder();
        SecureRandom instance = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(256, Capability.RESEED_ONLY, null));
        for (int i = 0; i < codeLength; i++) {
            result.append(instance.nextInt(9));
        }
        return result.toString();
    }

    /**
     * 随机生成字符串.
     *
     * @param strLength 字符串长度
     * @return 随机字符串
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     */
    public String randomStrBuilder(int strLength) throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(256, Capability.RESEED_ONLY, null));
        if (strLength < 1) {
            throw new IllegalArgumentException();
        }
        StringBuilder sb = new StringBuilder(strLength);
        for (int i = 0; i < strLength; i++) {
            int rndCharAt = random.nextInt(DATA_FOR_RANDOM_STRING.length());
            char rndChar = DATA_FOR_RANDOM_STRING.charAt(rndCharAt);
            sb.append(rndChar);
        }
        return sb.toString();
    }
}
