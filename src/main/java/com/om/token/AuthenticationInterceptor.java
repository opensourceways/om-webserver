/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Service.TokenUserService;
import com.om.Vo.TokenUser;

import java.lang.reflect.Method;
import java.util.Date;
import java.util.HashMap;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class AuthenticationInterceptor implements HandlerInterceptor {
    /**
     * 静态 ObjectMapper 对象.
     */
    private static ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 自动注入 TokenUserService 服务.
     */
    @Autowired
    private TokenUserService userService;

    /**
     * 令牌用户密码.
     */
    @Value("${token.user.password}")
    private String tokenUserPassword;

    /**
     * 在请求处理之前调用，用于拦截请求.
     *
     * @param httpServletRequest  HTTP请求对象
     * @param httpServletResponse HTTP响应对象
     * @param object 对象
     * @return 是否继续处理请求的布尔值
     * @throws Exception 异常
     */
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest,
                             HttpServletResponse httpServletResponse, Object object) throws Exception {
        ServletOutputStream sos = httpServletResponse.getOutputStream();

        String community = httpServletRequest.getParameter("community");
        if (community == null) {
            return true;
        }

        if (!community.equalsIgnoreCase("openeuler")
                && !community.equalsIgnoreCase("opengauss")
                && !community.equalsIgnoreCase("mindspore")
                && !community.equalsIgnoreCase("openlookeng")) {
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
                String password = user.getPassword() + tokenUserPassword;
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
