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

package com.om.Service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.OneidDao;
import com.om.Dao.RedisDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Constant;
import com.om.Result.Result;
import com.om.Service.inter.UserCenterServiceInter;
import com.om.Utils.CodeUtil;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service("opengauss")
public class OpenGaussService implements UserCenterServiceInter {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    OneidDao oneidDao;

    @Autowired
    JavaMailSender mailSender;

    private static CodeUtil codeUtil;

    private static Map<String, MessageCodeConfig> error2code;

    private static Result result;

    private static Map<String, String> appId2Secret;

    private static ObjectMapper objectMapper;

    private static List<String> channels;

    private static String poolId;

    private static String poolSecret;

    @PostConstruct
    public void init() {
        codeUtil = new CodeUtil();
        error2code = authingUserDao.getErrorCode();
        appId2Secret = getApps();
        result = new Result();
        channels = getSendCodeChannel();
        objectMapper = new ObjectMapper();
        poolId = env.getProperty("opengauss.pool.key");
        poolSecret = env.getProperty("opengauss.pool.secret");
    }

    @Override
    public ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        try {
            String community = servletRequest.getParameter("community");
            String appId = servletRequest.getParameter("client_id");
            String userName = servletRequest.getParameter("userName");
            String phone = servletRequest.getParameter("account");
            String phoneCode = servletRequest.getParameter("code");
            String company = servletRequest.getParameter("company");

            HashMap<String, Object> userInfo = new HashMap<>();

            if (StringUtils.isBlank(company))
                return result(HttpStatus.BAD_REQUEST, null, "请输入正确的公司名", null);
            userInfo.put("company", company);

            // app校验
            if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
                return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

            // 用户名校验
            if (StringUtils.isBlank(userName))
                return result(HttpStatus.BAD_REQUEST, null, "用户名不能为空", null);
            if (oneidDao.isUserExists(poolId, poolSecret, userName, "username"))
                return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);
            userInfo.put("username", userName);

            // 手机号校验
            if (!phone.matches(Constant.PHONEREGEX))
                return result(HttpStatus.BAD_REQUEST, null, "请输入正确的手机号码", null);
            if (oneidDao.isUserExists(poolId, poolSecret, phone, "phone"))
                return result(HttpStatus.BAD_REQUEST, null, "该账号已注册", null);
            userInfo.put("phone", phone);

            // 验证码校验
            String codeTemp = (String) redisDao.get(phone + "_sendCode_" + community);
            if (codeTemp == null) {
                return result(HttpStatus.BAD_REQUEST, null, "验证码无效或已过期", null);
            }
            if (!codeTemp.equals(phoneCode)) {
                return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);
            }

            // 用户注册
            String userJsonStr = objectMapper.writeValueAsString(userInfo);
            JSONObject user = oneidDao.createUser(poolId, poolSecret, userJsonStr);
            if (user == null)
                return result(HttpStatus.BAD_REQUEST, null, "注册失败", null);
            else
                return result(HttpStatus.OK, null, "success", null);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.INTERNAL_SERVER_ERROR, null, "Internal Server Error", null);
        }
    }

    @Override
    public ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess) {
        try {
            String community = servletRequest.getParameter("community");
            String account = servletRequest.getParameter("account");
            String channel = servletRequest.getParameter("channel");

            // 验证码二次校验
            if (!isSuccess)
                return result(HttpStatus.BAD_REQUEST, null, "验证码不正确", null);

            // 限制1分钟只能发送一次
            String redisKey = account + "_sendCode_" + community;
            String codeOld = (String) redisDao.get(redisKey);
            if (codeOld != null) {
                return result(HttpStatus.BAD_REQUEST, null, "一分钟之内已发送过验证码", null);
            }

            // channel校验
            if (StringUtils.isBlank(channel) || !channels.contains(channel.toLowerCase())) {
                return result(HttpStatus.BAD_REQUEST, null, "channel error", null);
            }

            // 发送验证码
            String accountType = getAccountType(account);
            String[] strings = codeUtil.sendCode(accountType, account, mailSender, env);
            if (StringUtils.isBlank(strings[0]) || !strings[2].equals("send code success"))
                return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);

            redisDao.set(redisKey, strings[0], Long.parseLong(strings[1]));
            return result(HttpStatus.OK, null, strings[2], null);
        } catch (Exception e) {
            return result(HttpStatus.BAD_REQUEST, null, "验证码发送失败", null);
        }
    }

    @Override
    public ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String community = servletRequest.getParameter("community");
        String appId = servletRequest.getParameter("client_id");
        String userName = servletRequest.getParameter("userName");
        String account = servletRequest.getParameter("account");

        // app校验
        if (StringUtils.isBlank(appId) || appId2Secret.getOrDefault(appId, null) == null)
            return result(HttpStatus.NOT_FOUND, null, "应用未找到", null);

        if (StringUtils.isNotBlank(userName)) {
            boolean username = oneidDao.isUserExists(poolId, poolSecret, userName, "username");
            if (username) return result(HttpStatus.BAD_REQUEST, null, "用户名已存在", null);
        } else if (StringUtils.isNotBlank(account)) {
            String accountType = checkPhoneAndEmail(poolId, poolSecret, account);
            if (!accountType.equals("email") && !accountType.equals("phone"))
                return result(HttpStatus.BAD_REQUEST, null, accountType, null);
        }
        return result(HttpStatus.OK, null, "success", null);
    }

    private String getAccountType(String account) {
        String accountType;
        if (account.matches(Constant.EMAILREGEX))
            accountType = "email";
        else if (account.matches(Constant.PHONEREGEX))
            accountType = "phone";
        else
            accountType = "请输入正确的手机号或者邮箱";

        return accountType;
    }

    private String checkPhoneAndEmail(String poolId, String poolSecret, String account) {
        String accountType = getAccountType(account);
        if (!accountType.equals("email") && !accountType.equals("phone"))
            return accountType;

        if (oneidDao.isUserExists(poolId, poolSecret, account, accountType))
            return "该账号已注册";
        else
            return accountType;
    }

    private Map<String, String> getApps() {
        HashMap<String, String> res = new HashMap<>();
        String property = env.getProperty("opengauss.apps");
        String[] split = property.split(";");
        for (String s : split) {
            String[] app = s.split(":");
            res.put(app[0], app[1]);
        }
        return res;
    }

    private List<String> getSendCodeChannel() {
        ArrayList<String> channels = new ArrayList<>();
        String property = env.getProperty("oneid.send.code.channel");
        for (String chanel : property.split(",")) {
            channels.add("channel_" + chanel);
        }
        return channels;
    }

    private ResponseEntity result(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data) {
        return result.setResult(status, msgCode, msg, data, error2code);
    }
}
