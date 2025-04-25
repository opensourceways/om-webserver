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
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class LogUtil {
    private static final Logger logger = LoggerFactory.getLogger(LogUtil.class);

    /**
     * 不记录日志的 URL 白名单列表.
     */
    public static final List<String> URL_NO_LOG_WHITE_LIST = Collections.unmodifiableList(new ArrayList<>() {
        {
            add("/oneid/checkOmService");
            add("/oneid/privacy/version");
        }
    });

    public static void managementOperate(JoinPoint joinPoint, HttpServletRequest request, HttpServletResponse response, Object returnObject) {
        if (URL_NO_LOG_WHITE_LIST.contains(CommonUtil.getSafeRequestUri(request))) {
            return;
        }
        ManagementLog log = new ManagementLog();
        log.setType("OmOperate");

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        log.setTime(dateTime.format(formatter));

        log.setFunc(String.format("%s.%s", joinPoint.getSignature().getDeclaringTypeName(), joinPoint.getSignature().getName()));

        log.setRequestUrl(request.getRequestURI());
        log.setMethod(request.getMethod());

        log.setAppIP(ClientIPUtil.getClientIpAddress(request));

        if (returnObject instanceof ResponseEntity) {
            ResponseEntity responseEntity = (ResponseEntity) returnObject;
            log.setStatus(responseEntity.getStatusCodeValue());
            if (responseEntity.getBody() instanceof HashMap) {
                HashMap<String, Object> body = (HashMap) responseEntity.getBody();
                Object msg = (body.get("msg") == null)?
                              body.get("message") : 
                              body.get("msg");
                log.setMessage((msg == null)? "" : msg.toString());
            }
        }

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

    /**
     * 组装记录日志.
     *
     * @param userId 用户id
     * @param type 操作类型
     * @param module 模块名
     * @param detail 操作资源详情
     * @param ip 操作者ip
     * @param result 操作结果
     */
    public static void createLogs(String userId, String type, String module, String detail, String ip, String result) {
        StringBuilder account = new StringBuilder();
        if (StringUtils.isNotBlank(userId)) {
            if (userId.matches((Constant.PHONEREGEX))) {
                account.append("****").append(userId.substring(userId.length() - 4));
            } else if (userId.matches(Constant.EMAILREGEX)) {
                int atIndex = userId.indexOf('@');
                if (atIndex > 1) {
                    account.append(userId.charAt(0)).append("****").append(userId.charAt(atIndex - 1))
                            .append(userId.substring(atIndex));
                } else {
                    account.append(userId);
                }
            } else {
                account.append(userId);
            }
        }
        logger.info(String.format("(Client ip:%s, User:%s, Module:%s, Type:%s) Detail:%s.--->Result:%s.",
                ip, account.toString(), module, type, detail, result));
    }

}