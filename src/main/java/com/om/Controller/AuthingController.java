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

package com.om.Controller;

import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Result.Constant;
import com.om.Service.AuthingService;
import com.om.Service.QueryService;
import com.om.Service.UserCenterServiceContext;
import com.om.Service.inter.UserCenterServiceInter;
import com.om.Utils.HttpClientUtils;
import com.om.authing.AuthingUserToken;
import com.om.token.ManageToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

import static com.anji.captcha.controller.CaptchaController.getRemoteId;


@RequestMapping(value = "/oneid")
@RestController
public class AuthingController {
    @Autowired
    AuthingService authingService;

    @Autowired
    QueryService queryService;

    @Autowired
    UserCenterServiceContext userCenterServiceContext;

    @Autowired
    private CaptchaService captchaService;

    @RequestMapping(value = "/captcha/get")
    public ResponseModel captchaGet(@RequestBody CaptchaVO data, HttpServletRequest request) {
        data.setBrowserInfo(getRemoteId(request));
        return captchaService.get(data);
    }

    @RequestMapping(value = "/captcha/check")
    public ResponseModel captchaCheck(@RequestBody CaptchaVO data, HttpServletRequest request) {
        data.setBrowserInfo(getRemoteId(request));
        return captchaService.check(data);
    }

    @RequestMapping(value = "/account/exists")
    public ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.accountExists(servletRequest, servletResponse);
    }

    @RequestMapping(value = {"/captcha/sendCode", "/v3/sendCode"})
    public ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                     @RequestParam("captchaVerification") String captchaVerification) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.sendCodeV3(servletRequest, servletResponse, verifyCaptcha(captchaVerification));
    }

    @RequestMapping(value = "/captcha/checkLogin")
    public ResponseEntity captchaLogin(HttpServletRequest servletRequest) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.captchaLogin(servletRequest);
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.register(servletRequest, servletResponse);
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity login(HttpServletRequest servletRequest,
                                HttpServletResponse servletResponse,
                                @RequestBody Map<String, Object> body) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.login(servletRequest, servletResponse, verifyCaptcha((String) body.get("captchaVerification")));
    }

    @RequestMapping(value = "/app/verify")
    public ResponseEntity appVerify(@RequestParam(value = "client_id") String clientId,
                                    @RequestParam(value = "redirect_uri") String redirect) {
        return authingService.appVerify(clientId, redirect);
    }

    @AuthingUserToken
    @RequestMapping(value = "/oidc/auth", method = RequestMethod.GET)
    public ResponseEntity oidcAuth(@CookieValue(value = "_Y_G_", required = false) String token,
                                   @RequestParam(value = "client_id") String clientId,
                                   @RequestParam(value = "redirect_uri") String redirectUri,
                                   @RequestParam(value = "response_type") String responseType,
                                   @RequestParam(value = "state", required = false) String state,
                                   @RequestParam(value = "scope") String scope) {
        return authingService.oidcAuth(token, clientId, redirectUri, responseType, state, scope);
    }

    @RequestMapping(value = "/oidc/authorize", method = RequestMethod.GET)
    public ResponseEntity oidcAuthorize(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        return authingService.oidcAuthorize(servletRequest, servletResponse);
    }

    @RequestMapping(value = "/oidc/token", method = RequestMethod.POST)
    public ResponseEntity oidcToken(HttpServletRequest servletRequest) {
        return authingService.oidcToken(servletRequest);
    }

    @RequestMapping(value = "/oidc/user")
    public ResponseEntity oidcUser(HttpServletRequest servletRequest) {
        return authingService.userByAccessToken(servletRequest);
    }

    @AuthingUserToken
    @RequestMapping(value = "/logout")
    public ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                 @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.logout(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/refresh")
    public ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                      @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.refreshUser(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/permission")
    public ResponseEntity getUser(@RequestParam(value = "community") String community,
                                  @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.authingUserPermission(community, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/permissions")
    public ResponseEntity userPermissions(@RequestParam(value = "community") String community,
                                          @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.userPermissions(community, token);
    }

    @RequestMapping(value = "/token/apply")
    public ResponseEntity tokenApply(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse,
                                     @RequestParam(value = "community") String community,
                                     @RequestParam(value = "code") String code,
                                     @RequestParam(value = "permission") String permission,
                                     @RequestParam(value = "redirect") String redirect) {
        return authingService.tokenApply(httpServletRequest, servletResponse, community, code, permission, redirect);
    }

    @AuthingUserToken
    @RequestMapping(value = "/personal/center/user")
    public ResponseEntity userInfo(HttpServletRequest servletRequest,
                                   HttpServletResponse servletResponse,
                                   @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.personalCenterUserInfo(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/delete/user")
    public ResponseEntity deleteUser(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse,
                                     @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(httpServletRequest);
        return service.deleteUser(httpServletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/sendcode")
    public ResponseEntity sendCode(@RequestParam(value = "account") String account,
                                   @RequestParam(value = "channel") String channel,
                                   @CookieValue(value = "_Y_G_", required = false) String token,
                                   @RequestParam("captchaVerification") String captchaVerification) {
        return authingService.sendCode(token, account, channel, verifyCaptcha(captchaVerification));
    }

    @AuthingUserToken
    @RequestMapping(value = "/sendcode/unbind")
    public ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest,
                                         HttpServletResponse servletResponse) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        String captchaVerification = servletRequest.getParameter("captchaVerification");
        return service.sendCodeUnbind(servletRequest, servletResponse, verifyCaptcha(captchaVerification));
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/account")
    public ResponseEntity updateAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse,
                                        @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.updateAccount(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unbind/account")
    public ResponseEntity unbindAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse,
                                        @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.unbindAccount(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/bind/account")
    public ResponseEntity bindAccount(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse,
                                      @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.bindAccount(servletRequest, servletResponse, token);
    }


    @AuthingUserToken
    @RequestMapping(value = "/conn/list")
    public ResponseEntity linkConnList(@CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.linkConnList(token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/link/account")
    public ResponseEntity linkAccount(@CookieValue(value = "_Y_G_", required = false) String token,
                                      @RequestParam(value = "secondtoken") String secondtoken) {
        return authingService.linkAccount(token, secondtoken);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unlink/account")
    public ResponseEntity unLinkAccount(@CookieValue(value = "_Y_G_", required = false) String token,
                                        @RequestParam(value = "platform") String platform) {
        return authingService.unLinkAccount(token, platform);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/baseInfo", method = RequestMethod.POST)
    public ResponseEntity updateUserBaseInfo(HttpServletRequest servletRequest,
                                             HttpServletResponse servletResponse,
                                             @CookieValue(value = "_Y_G_", required = false) String token,
                                             @RequestBody Map<String, Object> map) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.updateUserBaseInfo(servletRequest, servletResponse, token, map);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/photo", method = RequestMethod.POST)
    public ResponseEntity upload(HttpServletRequest servletRequest,
                                 HttpServletResponse servletResponse,
                                 @CookieValue(value = "_Y_G_", required = false) String token,
                                 @RequestParam(value = "file") MultipartFile file) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.updatePhoto(servletRequest, servletResponse, token, file);
    }

    @ManageToken
    @RequestMapping("/user/ownertype")
    public String queryUserOwnerType(@RequestParam(value = "community") String community,
                                     @RequestParam(value = "user", required = false) String user,
                                     @RequestParam(value = "username", required = false) String username)
            throws JsonProcessingException {
        String res = queryService.queryUserOwnertype(community, user, username);
        return res;
    }

    @RequestMapping(value = "/public/key", method = RequestMethod.GET)
    public ResponseEntity getPublicKey(HttpServletRequest request) {
        UserCenterServiceInter service = getServiceImpl(request);
        return service.getPublicKey();
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/password", method = RequestMethod.POST)
    public ResponseEntity updatePassword(HttpServletRequest request) {
        UserCenterServiceInter service = getServiceImpl(request);
        return service.updatePassword(request);
    }

    @RequestMapping(value = "/reset/password/verify", method = RequestMethod.POST)
    public ResponseEntity resetPwdVerify(HttpServletRequest request) {
        UserCenterServiceInter service = getServiceImpl(request);
        return service.resetPwdVerify(request);
    }

    @RequestMapping(value = "/reset/password", method = RequestMethod.POST)
    public ResponseEntity resetPwd(HttpServletRequest request) {
        UserCenterServiceInter service = getServiceImpl(request);
        return service.resetPwd(request);
    }

    private UserCenterServiceInter getServiceImpl(HttpServletRequest servletRequest) {
        String community = servletRequest.getParameter("community");
        if (community == null) {
            Map<String, Object> body = HttpClientUtils.getBodyFromRequest(servletRequest);
            community = (String) body.getOrDefault("community", null);
        }

        String serviceType =
                (community == null
                        || community.toLowerCase().equals(Constant.ONEID_VERSION_V1)
                        || community.toLowerCase().equals(Constant.ONEID_VERSION_V2))
                        ? Constant.AUTHING : community.toLowerCase();
        return userCenterServiceContext.getUserCenterService(serviceType);
    }

    private boolean verifyCaptcha(String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        return response.isSuccess();
    }
}
