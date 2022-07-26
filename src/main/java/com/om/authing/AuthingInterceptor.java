package com.om.authing;

import cn.authing.core.types.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.Date;


public class AuthingInterceptor implements HandlerInterceptor {
    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    RedisDao redisDao;

    @Value("${authing.token.base.password}")
    private String authingTokenBasePassword;

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        ServletOutputStream sos = httpServletResponse.getOutputStream();

        //从http请求头中取出 token
        String token = httpServletRequest.getHeader("token");

        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        // 检查有没有需要用户权限的注解
        if (method.isAnnotationPresent(AuthingToken.class)) {
            AuthingToken userLoginToken = method.getAnnotation(AuthingToken.class);
            // 执行认证
            if (userLoginToken.required()) {
                // token 为空
                if (token == null) {
                    httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token miss");
                    return false;
                }

                // 解析token
                String userId;
                Date issuedAt;
                Date expiresAt;
                String permission;
                try {
                    DecodedJWT decode = JWT.decode(token);
                    userId = decode.getAudience().get(0);
                    issuedAt = decode.getIssuedAt();
                    expiresAt = decode.getExpiresAt();
                    String permissionTemp = decode.getClaim("permission").asString();
                    permission = new String(Base64.getDecoder().decode(permissionTemp.getBytes()));
                } catch (JWTDecodeException j) {
                    httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
                    return false;
                }

                // 退出登录后token失效
                String redisKey = userId + issuedAt.toString();
                String beforeToken = (String) redisDao.get(redisKey);
                if (token.equalsIgnoreCase(beforeToken)) {
                    httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
                    return false;
                }

                // token 是否过期
                if (expiresAt.before(new Date())) {
                    httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token expires");
                    return false;
                }

                // token 签名密码验证
                String password = permission + authingTokenBasePassword;
                JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(password)).build();
                try {
                    jwtVerifier.verify(token);
                } catch (JWTVerificationException e) {
                    httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
                    return false;
                }

                // token 用户和权限验证
                try {
                    User user = authingUserDao.getUser(userId);
                    // token 签名接受者有误
                    if (user == null) {
                        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
                        return false;
                    }

                    // token 页面请求权限验证
                    String[] split = permission.split("->");
                    boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
                    if (!hasActionPer) {
                        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
                        return false;
                    }
                } catch (Exception e) {
                    httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
                    return false;
                }
                return true;
            }
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest,
                           HttpServletResponse httpServletResponse,
                           Object o, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest,
                                HttpServletResponse httpServletResponse,
                                Object o, Exception e) throws Exception {
    }
}