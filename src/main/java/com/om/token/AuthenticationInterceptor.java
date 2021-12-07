package com.om.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.*;
import com.om.Service.TokenUserService;
import com.om.Vo.TokenUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Date;
import java.util.HashMap;

public class AuthenticationInterceptor implements HandlerInterceptor {
    static ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    TokenUserService userService;
    @Autowired
    private openEuler openeuler;
    @Autowired
    private openGauss opengauss;
    @Autowired
    private openLookeng openlookeng;
    @Autowired
    private mindSpore mindspore;

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        ServletOutputStream sos = httpServletResponse.getOutputStream();

        String community = httpServletRequest.getParameter("community");
        openComObject communityObj;
        switch (community.toLowerCase()) {
            case "openeuler":
                communityObj = openeuler;
                break;
            case "opengauss":
                communityObj = opengauss;
                break;
            case "openlookeng":
                communityObj = openlookeng;
                break;
            case "mindspore":
                communityObj = mindspore;
                break;
            default:
                sos.write(errorToken(401, "token error"));
                return false;
        }

        //从http请求头中取出 token
        String token = httpServletRequest.getHeader("token");

        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        //检查是否有passToken注释，有则跳过认证
        if (method.isAnnotationPresent(PassToken.class)) {
            PassToken passToken = method.getAnnotation(PassToken.class);
            if (passToken.required()) {
                return true;
            }
        }
        //检查有没有需要用户权限的注解
        if (method.isAnnotationPresent(UserLoginToken.class)) {
            UserLoginToken userLoginToken = method.getAnnotation(UserLoginToken.class);
            if (userLoginToken.required()) {
                //执行认证
                if (token == null) {
                    sos.write(errorToken(401, "token is null")); // token 为空
                    return false;
                }

                String userName;  //获取token中的user name
                try {
                    DecodedJWT decode = JWT.decode(token);
                    userName = decode.getAudience().get(0);
                    Date expiresAt = decode.getExpiresAt();
                    if (expiresAt.before(new Date())) {
                        sos.write(errorToken(401, "token error"));  // token 过期
                        return false;
                    }
                } catch (JWTDecodeException j) {
                    sos.write(errorToken(401, "token error")); // token 无接受签名
                    return false;
                }
                TokenUser user = userService.findByUsername(community, userName);
                if (user == null) {
                    sos.write(errorToken(401, "token error")); // token 签名接受者有误
                    return false;
                }

                String password = user.getPassword() + communityObj.getTokenBasePassword();
                //验证token
                JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(password)).build();
                try {
                    jwtVerifier.verify(token);
                } catch (JWTVerificationException e) {
                    sos.write(errorToken(401, "token error")); // token 签名有误
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

    private byte[] errorToken(int status, String msg) {
        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", status);
        resMap.put("msg", msg);
        String resStr = objectMapper.valueToTree(resMap).toString();
        return resStr.getBytes();
    }
}