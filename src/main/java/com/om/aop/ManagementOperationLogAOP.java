package com.om.aop;

import com.om.Utils.LogUtil;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * AOP 切面类，用于管理操作日志记录.
 */
@Aspect
@Component
public class ManagementOperationLogAOP {

    /**
     * HTTP 请求对象，用于接收客户端请求信息.
     */
    @Autowired
    private HttpServletRequest request;

    /**
     * HTTP 响应对象，用于向客户端发送响应信息.
     */
    @Autowired
    private HttpServletResponse response;


    /**
     * 定义切点，匹配 com.om.Controller 包下所有类的所有方法.
     */
    @Pointcut("execution(* com.om.Controller.*.*(..))")
    public void pointcut() {
    }

    /**
     * 在切点方法执行返回后执行，用于处理方法返回结果.
     *
     * @param joinPoint 切点信息
     * @param returnObject 切点方法的返回值
     */
    @AfterReturning(pointcut = "pointcut()", returning = "returnObject")
    public void afterReturning(JoinPoint joinPoint, Object returnObject) {
        LogUtil.managementOperate(joinPoint, request, response, returnObject);
    }

}
