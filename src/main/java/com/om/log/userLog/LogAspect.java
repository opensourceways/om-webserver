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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.UserBehaviorLog;
import com.om.Utils.HttpClientUtils;
import com.om.log.LogCollector;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Aspect
@Component
public class LogAspect {
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private LogCollector logCollector;

    @Autowired
    private HttpServletRequest request;

    private static final String MSG_DEFAULT = "Internal Server Error";

    /**
     * 定义切点
     */
    @Pointcut("execution(* com.om.Controller..*.*(..))")
    public void log() {
    }

    /**
     * 循环通知
     *
     * @param joinPoint     切点
     * @param logAnnotation 自定义注解
     * @return 目标方法执行结果
     * @throws Throwable 抛出异常
     */
    @Around(value = "log() && @annotation(logAnnotation)")
    public Object around(ProceedingJoinPoint joinPoint, LogAnnotation logAnnotation) throws Throwable {
        // 目标方法执行前，初始化用户操作日志
        UserBehaviorLog userBehaviorLog = beforeAdviceMethod(logAnnotation);

        // 执行目标接口
        Object object = joinPoint.proceed();

        // 目标方法执行后，获取执行结果
        userBehaviorLog = afterAdviceMethod(userBehaviorLog, object);

        // 请求参数、body、cookies
        Map<String, Object> body = HttpClientUtils.getBodyFromRequest(request);
        Map<String, String[]> parameters = request.getParameterMap();
        Cookie[] cookies = request.getCookies();

        String ip = request.getHeader("x-forwarded-for");
        ip = (StringUtils.isBlank(ip) || "unknown".equalsIgnoreCase(ip)) ? request.getRemoteAddr() : ip;
        body.put("ip", ip);

        // 调用异步方法，整理日志以及入库
        logCollector.pushToKafka(userBehaviorLog, body, parameters, cookies);

        return object;
    }

    private UserBehaviorLog beforeAdviceMethod(LogAnnotation logAnnotation) {
        return new UserBehaviorLog()
                .setEventType(logAnnotation.methodType().getType())
                .setEventName(logAnnotation.methodType().getName())
                .setSuccess(false)
                .setMessage(MSG_DEFAULT)
                .setTimestamp(System.currentTimeMillis())
                .setPath(request.getServletPath());
    }

    private UserBehaviorLog afterAdviceMethod(UserBehaviorLog userBehaviorLog, Object object)
            throws JsonProcessingException {
        if (object instanceof ResponseEntity) {
            ResponseEntity res = (ResponseEntity) object;
            if (res.getStatusCodeValue() == 200) {
                userBehaviorLog.setSuccess(true).setMessage("success");
            } else {
                String bodyStr = JSONObject.valueToString(res.getBody());
                String msg = objectMapper.readTree(bodyStr).get("msg").get("message_en").asText();
                userBehaviorLog.setMessage(msg);
            }
        }

        return userBehaviorLog;
    }

    private String getRemoteIp() {
        String ip = request.getHeader("x-forwarded-for");
        return (StringUtils.isBlank(ip) || "unknown".equalsIgnoreCase(ip))
                ? request.getRemoteAddr()
                : ip;
    }
}
