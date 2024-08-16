/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.utils;

import com.alibaba.fastjson2.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.result.Constant;
import com.om.vo.ManagementLog;

import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.JoinPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import java.util.ArrayList;
import java.util.Objects;

public final class LogUtil {

    private LogUtil() {
        throw new AssertionError("Utility class. Not intended for instantiation.");
    }

    /**
     * 日志记录器，用于记录 LogUtil 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LogUtil.class);

    /**
     * 不记录日志的 URL 白名单列表.
     */
    public static final List<String> URL_NO_LOG_WHITE_LIST = Collections.unmodifiableList(new ArrayList<>() {
        {
            add("/oneid/checkOmService");
        }
    });

    /**
     * 管理操作，处理连接点、请求、响应和返回对象.
     *
     * @param joinPoint    切入点
     * @param request      HTTP请求对象
     * @param response     HTTP响应对象
     * @param returnObject 返回对象
     */
    public static void managementOperate(JoinPoint joinPoint, HttpServletRequest request,
                                         HttpServletResponse response, Object returnObject) {
        if (URL_NO_LOG_WHITE_LIST.contains(request.getRequestURI())) {
            return;
        }
        ManagementLog log = new ManagementLog();
        log.setType("OmOperate");

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        log.setTime(dateTime.format(formatter));

        log.setFunc(String.format("%s.%s",
                joinPoint.getSignature().getDeclaringTypeName(), joinPoint.getSignature().getName()));

        log.setRequestUrl(request.getRequestURI());
        log.setMethod(request.getMethod());

        log.setAppIP(ClientIPUtil.getClientIpAddress(request));

        if (returnObject instanceof ResponseEntity) {
            ResponseEntity responseEntity = (ResponseEntity) returnObject;
            log.setStatus(responseEntity.getStatusCodeValue());
            if (responseEntity.getBody() instanceof HashMap) {
                HashMap<String, Object> body = (HashMap) responseEntity.getBody();
                Object msg = null;
                if (Objects.nonNull(body)) {
                    msg = body.getOrDefault("msg", body.get("message"));
                }

                log.setMessage((msg == null) ? "" : msg.toString());
            }
        }

        log.setOperator(getUserId(request, response));

        String jsonLog = JSON.toJSONString(log);
        LOGGER.info("operationLog:{}", jsonLog);
    }

    /**
     * 获取用户ID.
     *
     * @param request  HTTP请求对象
     * @param response HTTP响应对象
     * @return 用户ID字符串
     */
    public static String getUserId(HttpServletRequest request, HttpServletResponse response) {
        // 从token中获取
        String token = request.getHeader("token");
        if (StringUtils.isBlank(token)) {
            Collection<String> cookies = response.getHeaders("Set-Cookie");
            if (cookies != null) {
                for (String cookie : cookies) {
                    if (cookie.contains(Constant.TOKEN_U_T)) {
                        token = cookie.split(";")[0].replace(Constant.TOKEN_U_T + "=", "");
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
                LOGGER.info("Log using token fail");
            }
        }

        // 从param中获取
        String[] idKey = {"username"};
        for (String key : idKey) {
            String userId = request.getParameter(key);
            if (StringUtils.isNotBlank(userId)) {
                return userId;
            }
        }

        // 从body中获取
        for (String key : idKey) {
            Object userId = request.getAttribute(key);
            if (userId != null) {
                return userId.toString();
            }
        }
        return "";
    }

    /**
     * format logging parameter.
     *
     * @param input The input pramater
     * @return formatedOutput The safe output logging parmeter
     */
    public static String formatCodeString(String input) {
        if (input == null) {
            return input;
        }
        String formatedOutput = input.replace("\r", "\\r").replace("\n", "\\n").replace("\u0008", "\\u0008")
                .replace("\u000B", "\\u000B")
                .replace("\u000C", "\\u000C")
                .replace("\u007F", "\\u007F")
                .replace("\u0009", "\\u0009");
        return formatedOutput;
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
        LOGGER.info(String.format("(Client ip:%s, User id:%s, Module:%s, Type:%s) Detail:%s.--->Result:%s.",
                ip, userId, module, type, detail, result));
    }
}
