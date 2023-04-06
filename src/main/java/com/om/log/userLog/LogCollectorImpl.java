/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.log.userLog;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.KafkaDao;
import com.om.Modules.UserBehaviorLog;
import com.om.Result.Constant;
import com.om.Utils.RSAUtil;
import com.om.log.LogCollector;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class LogCollectorImpl implements LogCollector {
    @Autowired
    private Environment env;

    @Autowired
    private KafkaDao kafkaDao;

    @Autowired
    private ObjectMapper objectMapper;

    @Async
    @Override
    public void pushToKafka(UserBehaviorLog userBehaviorLog, Map<String, Object> parameterMap,
                            Map<String, String[]> parameters, Cookie[] cookies) throws Exception {
        // 获取请求参数
        UserBehaviorLog logBean = createLog(userBehaviorLog, parameterMap, parameters, cookies);

        // 推送日志到kafka
        String property = env.getProperty("log.kafka.topic");
        String id = UUID.randomUUID().toString();
        String logStr = objectMapper.writeValueAsString(logBean);
        kafkaDao.sendMess(property, id, logStr);
    }

    private UserBehaviorLog createLog(UserBehaviorLog userBehaviorLog,
                                      Map<String, Object> parameterMap,
                                      Map<String, String[]> parameters,
                                      Cookie[] cookies) throws Exception {
        // request parameters获取值
        Map<String, String> paraMap = parameters.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue()[0]));
        parameterMap.putAll(paraMap);

        // cookie中取值
        if (cookies != null) {
            Optional<Cookie> first = Arrays.stream(cookies)
                    .filter(cookie -> cookie.getName().equals(env.getProperty("cookie.token.name"))).findFirst();
            if (first.isPresent()) {
                RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
                DecodedJWT decode = JWT.decode(RSAUtil.privateDecrypt(first.get().getValue(), privateKey));
                parameterMap.put("user_id", Base64.getEncoder().encodeToString(decode.getAudience().get(0).getBytes()));
                parameterMap.put("client_id", decode.getClaim("client_id").asString());
            }
        }

        // 脱敏
        parameterMap = parameterMap.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,
                entry -> desensitization(entry.getKey(), entry.getValue())));

        // 输入参数加密
        String parameterJsonStr = objectMapper.writeValueAsString(parameterMap);
        RSAPublicKey publicKey = RSAUtil.getPublicKey(env.getProperty("rsa.authing.publicKey"));
        userBehaviorLog.setParameters(RSAUtil.publicEncrypt(parameterJsonStr, publicKey));

        return userBehaviorLog;
    }

    /**
     * 字符串脱敏
     *
     * @param key   EntryKey
     * @param value EntryValue
     * @return 脱敏后的value
     */
    private Object desensitization(String key, Object value) {
        if (key.matches(Constant.FULL_SENSITIVE_REG)) {
            return "******";
        } else if (key.matches(Constant.HALF_SENSITIVE_REG)) {
            return desensitizationAccount(value.toString());
        } else {
            return value;
        }
    }

    /**
     * 手机和邮箱脱敏
     *
     * @param account 账号
     * @return 脱敏后的账号
     */
    private String desensitizationAccount(String account) {
        if (StringUtils.isBlank(account)) {
            return "";
        }

        String res;
        if (account.matches(Constant.PHONEREGEX)) {
            res = account.replaceAll(Constant.PHONE_REPLACE_REG, "$1****$2");
        } else if (account.matches(Constant.EMAILREGEX)) {
            res = account.replaceAll(Constant.EMAIL_REPLACE_REG, "$1****$2");
        } else {
            res = account;
        }
        return res;
    }
}
