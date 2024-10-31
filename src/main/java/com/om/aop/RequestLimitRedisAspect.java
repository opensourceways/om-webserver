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

package com.om.aop;

import com.om.modules.MessageCodeConfig;
import com.om.result.Result;
import com.om.utils.ClientIPUtil;
import com.om.utils.CommonUtil;
import com.om.utils.LogUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;

@Aspect
@Component
public class RequestLimitRedisAspect {
    /**
     * Logger for logging messages in RequestLimitRedisAspect class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RequestLimitRedisAspect.class);

    /**
     * 请求返回.
     */
    private static Result result = new Result();

    /**
     * Autowired RedisTemplate for interacting with Redis.
     */
    @Autowired
    private RedisTemplate redisTemplate;

    /**
     * Value of the rejection period configured globally.
     */
    @Value("${dos-global.rejectPeriod:1}")
    private long rejectPeriod;

    /**
     * Value of the rejection count configured globally.
     */
    @Value("${dos-global.rejectCount:100}")
    private long rejectCount;

    /**
     * Pointcut method to define where the aspect applies based on the
     * RequestLimitRedis annotation.
     *
     * @param requestLimit The RequestLimitRedis annotation.
     */
    @Pointcut("@annotation(requestLimit)")
    public void controllerAspect(final RequestLimitRedis requestLimit) {
    }

    /**
     * Advice method that intercepts the method calls annotated with
     * RequestLimitRedis and enforces request limiting.
     *
     * @param joinPoint    The ProceedingJoinPoint representing the intercepted
     *                     method.
     * @param requestLimit The RequestLimitRedis annotation containing request
     *                     limiting criteria.
     * @return The result of the intercepted method execution.
     * @throws Throwable if an error occurs during method execution.
     */
    @Around("controllerAspect(requestLimit)")
    public Object before(final ProceedingJoinPoint joinPoint, final RequestLimitRedis requestLimit) throws Throwable {
        long period = rejectPeriod;
        long limitCount = rejectCount;
        if (requestLimit != null && requestLimit.count() > 0 && requestLimit.period() > 0) {
            period = requestLimit.period();
            limitCount = requestLimit.count();
        }

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = (attributes != null) ? attributes.getRequest() : null;
        if (request == null) {
            LOGGER.error("Failed to obtain HttpServletRequest in the current context.");
            return result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012);
        }

        // 获取url
        String ip = ClientIPUtil.getClientIpAddress(request);
        String uri = CommonUtil.getSafeRequestUri(request);
        String key = "req_limit:".concat(uri).concat(ip);

        ZSetOperations zSetOperations = redisTemplate.opsForZSet();

        long currentMs = System.currentTimeMillis();
        zSetOperations.add(key, currentMs, currentMs);

        redisTemplate.expire(key, period, TimeUnit.SECONDS);

        // remove the value that out of current window
        zSetOperations.removeRangeByScore(key, 0, currentMs - period * 1000);

        // 检查访问次数
        Long count = zSetOperations.zCard(key);

        if (count != null && count > limitCount) {
            // 审计日志
            LOGGER.error("the current uri is{}，the request frequency of uri exceeds the limited frequency: "
                    + "{} times/{}s ,IP：{},type: GET", LogUtil.formatCodeString(uri), limitCount, period, ip);
            return result(HttpStatus.TOO_MANY_REQUESTS, MessageCodeConfig.E00065);
        }

        return joinPoint.proceed();
    }

    private ResponseEntity result(HttpStatus status, MessageCodeConfig msgCode) {
        return result.setResult(status, msgCode, null, null, new HashMap<>());
    }
}
