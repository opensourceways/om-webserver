package com.om.Service;

import java.util.List;
import java.util.Arrays;
import java.util.Iterator;
import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.om.Dao.AuthingUserDao;
import com.om.Utils.CodeUtil;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class ErrorAlertService {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    private static CodeUtil codeUtil;
    public String msgsms_app_key;
    public String msgsms_app_secret;
    public String msgsms_url;
    public String msgsms_signature;
    public String msgsms_sender;
    public String msgsms_template_id;
    public String account;

    @PostConstruct
    public void init() {
        codeUtil = new CodeUtil();
        msgsms_app_key = env.getProperty("msgsms.app_key");
        msgsms_app_secret = env.getProperty("msgsms.app_secret");
        msgsms_url = env.getProperty("msgsms.url");
        msgsms_signature = env.getProperty("msgsms.signature");
        msgsms_sender = env.getProperty("msgsms.sender");
        msgsms_template_id = env.getProperty("msgsms.template.id");
        account = env.getProperty("account.phone");        
    }

    public Boolean errorAlert(String community, JsonNode old_data, JsonNode new_data) {
        Boolean flag = false;
        switch (community.toLowerCase()) {
            case "openeuler":
                break;
            case "opengauss":
                break;
            case "openlookeng":
                break;
            case "mindspore":
                break;
            default:
                return flag;
        }
        List<String> accounts = Arrays.asList(account.split(","));
        Iterator<String> fieldNames = old_data.fieldNames();
        while (fieldNames.hasNext()) {
            String fieldName = fieldNames.next();
            JsonNode old_value = old_data.get(fieldName);
            JsonNode new_value = new_data.get(fieldName);
            if (old_value == null || new_value == null) {
                for (String account : accounts) {
                    sendMsg(account, community, fieldName, null);
                }
                flag = true;
            } else if (old_value.asInt() > new_value.asInt()) {
                for (String account : accounts) {
                    sendMsg(account, community, fieldName, new_value.asText());
                }
                flag = true;
            }
        }
        return flag;
    }

    public void sendMsg(String account, String community, String field, String value) {

        // 短信发送服务器
        String template = "%s %s = %s";
        String msg = String.format(template, community, field, value);
        String resMsg = "send code fail";

        // 短信发送请求
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String format = dtf.format(LocalDateTime.now());
        String[] split = format.split(" ");
        String templateParas = String.format("[\"%s\",\"%s\",\"%s\"]", msg, split[0], split[1]);
        String wsseHeader = codeUtil.buildWsseHeader(msgsms_app_key, msgsms_app_secret);
        String body = codeUtil.buildSmsBody(msgsms_sender, account, msgsms_template_id, templateParas, "",
                msgsms_signature);
        // 发送验证码
        HttpResponse<com.mashape.unirest.http.JsonNode> response;
        try {
            response = Unirest.post(msgsms_url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", CodeUtil.AUTH_HEADER_VALUE)
                    .header("X-WSSE", wsseHeader)
                    .body(body)
                    .asJson();
            if (response.getStatus() == 200)
                resMsg = "send sms code success";

        } catch (UnirestException e) {
            e.printStackTrace();
        }
        System.out.println(resMsg);
    }
}
