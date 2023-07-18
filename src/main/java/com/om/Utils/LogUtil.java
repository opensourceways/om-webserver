package com.om.Utils;

import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Result.Constant;
import com.om.Vo.ManagementLog;

import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.JoinPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;

public class LogUtil {
    private static final Logger logger = LoggerFactory.getLogger(LogUtil.class);

    public static void managementOperate(JoinPoint joinPoint, int status, String message, HttpServletRequest request, HttpServletResponse response) {
        ManagementLog log = new ManagementLog();
        log.setType("OmOperate");

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        log.setTime(dateTime.format(formatter));

        log.setFunc(String.format("%s.%s", joinPoint.getSignature().getDeclaringTypeName(), joinPoint.getSignature().getName()));

        log.setRequestUrl(request.getRequestURI());
        log.setMethod(request.getMethod());

        log.setAppIP(ClientIPUtil.getClientIpAddress(request));

        log.setStatus(status);
        log.setMessage(message);

        log.setOperator(getUserId(request, response));

        String jsonLog = JSON.toJSONString(log);
        logger.info("operationLog:{}", jsonLog);
    }

    public static String getUserId(HttpServletRequest request, HttpServletResponse response) {
        // 从token中获取
        String token = request.getHeader("token");
        if (StringUtils.isBlank(token)) {
            Collection<String> cookies = response.getHeaders("Set-Cookie");
            if (cookies != null) {
                for (String cookie : cookies) {
                    if (cookie.contains(Constant.TOKEN_U_T_)) {
                        token = cookie.split(";")[0].replace(Constant.TOKEN_U_T_ + "=", "");
                    }
                }
            }
        }

        if (StringUtils.isNotBlank(token)) {
            try {
                DecodedJWT decode = JWT.decode(token);
                String userId = decode.getAudience().get(0);
                return userId;
            } catch (Exception e) {
                logger.info("Log using token fail");
            }
        }

        // 从param中获取
        String[] idKey = {"username"};
        for (String key: idKey) {
            String userId = request.getParameter(key);
            if (StringUtils.isNotBlank(userId)) return userId;
        }

        // 从body中获取
        for (String key : idKey) {
            Object userId = request.getAttribute(key);
            if (userId != null) return userId.toString();
        }
        return "";
    }
}