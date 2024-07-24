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

package com.om.authing;

import com.om.Result.Constant;
import com.om.token.ManageToken;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.lang.reflect.Method;

/**
 * 拦截器类，用于进行身份验证拦截.
 */
public class AuthingInterceptor implements HandlerInterceptor {
    /**
     * session管理器
     */
    @Autowired
    private SessionManager sessionManager;

    /**
     * 预处理方法，在请求处理之前调用，用于进行预处理操作.
     *
     * @param httpServletRequest  HTTP 请求对象
     * @param httpServletResponse HTTP 响应对象
     * @param object              处理器
     * @return 返回布尔值表示是否继续处理请求
     * @throws Exception 可能抛出的异常
     */
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest,
                             HttpServletResponse httpServletResponse, Object object) throws Exception {
        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }

        // 检查有没有需要用户权限的注解，仅拦截AuthingToken和AuthingUserToken
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        if (!method.isAnnotationPresent(AuthingUserToken.class)) {
            return true;
        }
        AuthingUserToken authingUserToken = method.getAnnotation(AuthingUserToken.class);
        if (authingUserToken == null || !authingUserToken.required()) {
            return true;
        }

        // get if manageToken present
        ManageToken manageToken = method.getAnnotation(ManageToken.class);
        boolean isRefreshCookie = true;
        String checkResult = "";
        if (manageToken != null && manageToken.required()) {
            checkResult = sessionManager.checkSession(httpServletRequest, httpServletResponse, false, true);
        } else {
            checkResult = sessionManager.checkSession(httpServletRequest, httpServletResponse, true, false);
        }
        if (Constant.SUCCESS.equals(checkResult)) {
            return true;
        } else {
            sessionManager.tokenError(httpServletRequest, httpServletResponse, checkResult);
            return false;
        }
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
