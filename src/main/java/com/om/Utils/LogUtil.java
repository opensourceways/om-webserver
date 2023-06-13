package com.om.Utils;

import com.alibaba.fastjson2.JSON;
import com.om.Vo.ManagementLog;
import org.aspectj.lang.JoinPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LogUtil {
    private static final Logger logger = LoggerFactory.getLogger(LogUtil.class);

    public static void managementOperate(JoinPoint joinPoint, int status, String message, HttpServletRequest request) {
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

        String jsonLog = JSON.toJSONString(log);
        logger.info("operationLog:{}", jsonLog);
    }
}