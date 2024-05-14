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

package com.om.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.RedisDao;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.lang.reflect.Method;

public class OneIdManageInterceptor implements HandlerInterceptor {
    /**
     * 自动注入环境变量.
     */
    @Autowired
    private Environment env;

    /**
     * 自动注入 Redis 数据访问对象.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 自动注入对象映射器 ObjectMapper.
     */
    @Autowired
    private ObjectMapper objectMapper;


    /**
     * 在请求处理之前调用，用于拦截请求.
     *
     * @param request  HTTP请求对象
     * @param response HTTP响应对象
     * @param handler  处理器对象
     * @return 是否继续处理请求的布尔值
     * @throws Exception 异常
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {
        // 如果不是映射到方法直接通过
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        // 检查有没有需要用户权限的注解，仅拦截AuthingToken和AuthingUserToken
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        Method method = handlerMethod.getMethod();
        if (!method.isAnnotationPresent(ManageToken.class)) {
            return true;
        }
        ManageToken manageToken = method.getAnnotation(ManageToken.class);
        if ((manageToken == null || !manageToken.required())) {
            return true;
        }

        // 校验token
        String token = request.getHeader("token");
        String tokenStr = (String) redisDao.get(token);
        if (StringUtils.isBlank(tokenStr)) {
            tokenError(response, "token error or expire");
            return false;
        }
        try {
            // 获取服务端token信息
            String tokenInfo = tokenStr.replace("token_info:", "");
            JsonNode jsonNode = objectMapper.readTree(tokenInfo);
            String appSecret = jsonNode.get("app_secret").asText();
            String tokenJwt = jsonNode.get("token").asText();

            // 校验refresh_token是否正确或过期
            String password = appSecret + env.getProperty("authing.token.base.password");
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(password)).build();
            jwtVerifier.verify(tokenJwt);

            return true;
        } catch (Exception e) {
            tokenError(response, "token error or expire");
            return false;
        }
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) throws Exception {

    }

    private void tokenError(HttpServletResponse response, String msg) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
    }
}
