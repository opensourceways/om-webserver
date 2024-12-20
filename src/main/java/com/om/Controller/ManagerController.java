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

package com.om.Controller;

import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.om.Controller.bean.request.PermissionInfo;
import com.om.Controller.bean.request.ResourceInfo;
import com.om.Controller.bean.request.NamespaceInfoPage;
import com.om.Service.AuthingService;
import com.om.Service.OneIdManageService;
import com.om.Vo.User;
import com.om.aop.RequestLimitRedis;
import com.om.authing.AuthingUserToken;
import com.om.token.ManageToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 管理员控制器，处理 "/oneid/manager" 路径下的请求.
 */
@RequestMapping(value = "/oneid/manager")
@RestController
public class ManagerController {
    /**
     * 日志记录器实例，用于记录 ManagerController 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ManagerController.class);

    /**
     * 间隔时间.
     */
    private static final int MANAGER_LIMIT_PERIOD = 1;

    /**
     * 调用次数.
     */
    private static final int MANAGER_LIMIT_COUNT = 1000;

    /**
     * 用于注入验证码服务的对象.
     */
    @Autowired
    private CaptchaService captchaService;

    /**
     * 用于注入 OneId 管理服务的对象.
     */
    @Autowired
    private OneIdManageService oneIdManageService;

    /**
     * 用于注入 Authing 服务的对象.
     */
    @Autowired
    private AuthingService authingService;

    /**
     * 处理令牌申请的方法.
     *
     * @param body 包含请求体信息的 Map 对象
     * @return 返回 ResponseEntity 对象
     */
    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity tokenApply(@RequestBody Map<String, String> body) {
        return oneIdManageService.tokenApply(body);
    }

    /**
     * 发送验证码的方法.
     *
     * @param body  包含请求体信息的 Map 对象
     * @param token 包含在请求头中的令牌字符串
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/sendcode", method = RequestMethod.POST)
    public ResponseEntity sendCode(@RequestBody Map<String, String> body,
                                   @RequestHeader(value = "token") String token) {
        return oneIdManageService.sendCode(body, token, verifyCaptcha((String) body.get("captchaVerification")));
    }

    /**
     * 绑定账号的方法.
     *
     * @param body  包含请求体信息的 Map 对象
     * @param token 包含在请求头中的令牌字符串
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/bind/account", method = RequestMethod.POST)
    public ResponseEntity bindAccount(@RequestBody Map<String, String> body,
                                      @RequestHeader(value = "token") String token) {
        return oneIdManageService.bindAccount(body, token);
    }

    /**
     * 身份验证的方法.
     *
     * @param community  社区参数（可选）
     * @param userCookie 用户 Cookie 值（可选）
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/authenticate", method = RequestMethod.GET)
    public ResponseEntity authenticate(
            @RequestParam(value = "community", required = false) String community,
            @CookieValue(value = "_Y_G_", required = false) String userCookie) {
        return oneIdManageService.authenticate(community, userCookie);
    }

    /**
     * 获取用户信息的方法.
     *
     * @param username    用户名（可选）
     * @param userId      用户ID（可选）
     * @param giteeLogin  Gitee 登录名（可选）
     * @param githubLogin GitHub 登录名（可选）
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/getuserinfo", method = RequestMethod.GET)
    public ResponseEntity getUser(
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "userId", required = false) String userId,
            @RequestParam(value = "giteeLogin", required = false) String giteeLogin,
            @RequestParam(value = "githubLogin", required = false) String githubLogin) {
        return oneIdManageService.getUserInfo(username, userId, giteeLogin, githubLogin);
    }

    /**
     * 获取用户权限信息的方法.
     *
     * @param community 社区参数（可选）
     * @param token     用户凭证 Cookie 值（可选）
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/u/permissions", method = RequestMethod.GET)
    public ResponseEntity getUserPermissions(
            @RequestParam(value = "community", required = false) String community,
            @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.userPermissions(community, token);
    }

    /**
     * 查询用户是否有权限.
     *
     * @param permissionInfo 请求体
     * @return 是否有权限
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/u/checkPermission", method = RequestMethod.POST)
    public ResponseEntity checkPermission(@RequestBody PermissionInfo permissionInfo) {
        return authingService.checkPermission(permissionInfo);
    }

    /**
     * 获取有权限的资源.
     *
     * @param permissionInfo 权限信息
     * @return 权限资源
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/u/getResources", method = RequestMethod.POST)
    public ResponseEntity getResources(@RequestBody PermissionInfo permissionInfo) {
        return authingService.getResources(permissionInfo);
    }

    /**
     * 获取权限分组下的资源列表.
     *
     * @param namespaceInfoPage 分页获取
     * @return 资源列表
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/permission/allResources", method = RequestMethod.POST)
    public ResponseEntity getAllResources(@RequestBody NamespaceInfoPage namespaceInfoPage) {
        return authingService.getAllResources(namespaceInfoPage);
    }

    /**
     * 获取某个资源的用户授权列表.
     *
     * @param resourceInfo 资源参数
     * @return 用户授权列表
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/permission/resource/userList", method = RequestMethod.POST)
    public ResponseEntity listUserOfResource(@RequestBody ResourceInfo resourceInfo) {
        return authingService.listUserOfResource(resourceInfo);
    }

    /**
     * 获取用户中心信息的方法.
     *
     * @param servletRequest  HTTP Servlet 请求对象
     * @param servletResponse HTTP Servlet 响应对象
     * @param token           用户凭证 Cookie 值（可选）
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/personal/center/user", method = RequestMethod.GET)
    public ResponseEntity getUserCenterInfo(
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse,
            @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.personalCenterUserInfo(servletRequest, servletResponse, token);
    }

    /**
     * 撤销隐私设置的方法.
     *
     * @param body 包含用户信息的请求体对象
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @RequestMapping(value = "/privacy/revoke", method = RequestMethod.POST)
    public ResponseEntity revokePrivacy(@RequestBody User body) {
        return oneIdManageService.revokePrivacy(body.getUserId());
    }

    /**
     * 处理更新账号信息请求的方法.
     *
     * @param servletRequest HTTP 请求对象
     * @param servletResponse HTTP 响应对象
     * @param token 包含令牌的 Cookie 值（可选）
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/update/account", method = RequestMethod.POST)
    public ResponseEntity updateAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse,
                                        @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.updateAccountPost(servletRequest, servletResponse, token);
    }

    /**
     * 直接更新账号信息.
     *
     * @param servletRequest HTTP 请求对象
     * @param servletResponse HTTP 响应对象
     * @param token 包含令牌的 Cookie 值（可选）
     * @return 返回 ResponseEntity 对象
     */
    @RequestLimitRedis(period = MANAGER_LIMIT_PERIOD, count = MANAGER_LIMIT_COUNT)
    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/update/accountInfo", method = RequestMethod.POST)
    public ResponseEntity updateAccountInfo(HttpServletRequest servletRequest,
                                            HttpServletResponse servletResponse,
                                            @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.updateAccountInfo(servletRequest, servletResponse, token);
    }

    private boolean verifyCaptcha(String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        if (response != null) {
            LOGGER.info("captcha response msg: " + response.getRepMsg() + "  "
                    + "captcha response status: " + response.isSuccess());
            return response.isSuccess();
        }
        return false;
    }
}
