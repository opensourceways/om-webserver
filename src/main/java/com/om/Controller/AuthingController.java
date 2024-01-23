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
import com.om.Result.Constant;
import com.om.Service.AuthingService;
import com.om.Service.QueryService;
import com.om.Service.UserCenterServiceContext;
import com.om.Service.inter.UserCenterServiceInter;
import com.om.Utils.HttpClientUtils;
import com.om.authing.AuthingUserToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

import static com.anji.captcha.Controller.CaptchaController.getRemoteId;;


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

    @RequestMapping(value = "/captcha/get", method = RequestMethod.POST)
    public ResponseModel captchaGet(@RequestBody CaptchaVO data, HttpServletRequest request) {
        data.setBrowserInfo(getRemoteId(request));
        return captchaService.get(data);
    }

    @RequestMapping(value = "/captcha/check", method = RequestMethod.POST)
    public ResponseModel captchaCheck(@RequestBody CaptchaVO data, HttpServletRequest request) {
        data.setBrowserInfo(getRemoteId(request));
        return captchaService.check(data);
    }

    @RequestMapping(value = "/account/exists", method = RequestMethod.GET)
    public ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.accountExists(servletRequest, servletResponse);
    }

    @RequestMapping(value = {"/captcha/sendCode", "/v3/sendCode"}, method = RequestMethod.GET)
    public ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                     @RequestParam("captchaVerification") String captchaVerification) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.sendCodeV3(servletRequest, servletResponse, verifyCaptcha(captchaVerification));
    }

    @RequestMapping(value = "/captcha/checkLogin", method = RequestMethod.GET)
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

    @RequestMapping(value = "/app/verify", method = RequestMethod.GET)
    public ResponseEntity appVerify(HttpServletRequest servletRequest,
                                    @RequestParam(value = "client_id") String clientId,
                                    @RequestParam(value = "redirect_uri") String redirect) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.appVerify(clientId, redirect);
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

    @RequestMapping(value = "/oidc/user", method = RequestMethod.GET)
    public ResponseEntity oidcUser(HttpServletRequest servletRequest) {
        return authingService.userByAccessToken(servletRequest);
    }

    @AuthingUserToken
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                 @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.logout(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/refresh", method = RequestMethod.GET)
    public ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                      @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.refreshUser(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/permission", method = RequestMethod.GET)
    public ResponseEntity getUser(@RequestParam(value = "community") String community,
                                  @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.authingUserPermission(community, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/permissions", method = RequestMethod.GET)
    public ResponseEntity userPermissions(@RequestParam(value = "community") String community,
                                          @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.userPermissions(community, token);
    }

    @RequestMapping(value = "/token/apply", method = RequestMethod.GET)
    public ResponseEntity tokenApply(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse,
                                     @RequestParam(value = "community") String community,
                                     @RequestParam(value = "code") String code,
                                     @RequestParam(value = "permission") String permission,
                                     @RequestParam(value = "redirect") String redirect) {
        return authingService.tokenApply(httpServletRequest, servletResponse, community, code, permission, redirect);
    }

    @AuthingUserToken
    @RequestMapping(value = "/personal/center/user", method = RequestMethod.GET)
    public ResponseEntity userInfo(HttpServletRequest servletRequest,
                                   HttpServletResponse servletResponse,
                                   @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.personalCenterUserInfo(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/delete/user", method = RequestMethod.GET)
    public ResponseEntity deleteUser(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse,
                                     @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(httpServletRequest);
        return service.deleteUser(httpServletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/sendcode", method = RequestMethod.GET)
    public ResponseEntity sendCode(@RequestParam(value = "account") String account,
                                   @RequestParam(value = "channel") String channel,
                                   @CookieValue(value = "_Y_G_", required = false) String token,
                                   @RequestParam("captchaVerification") String captchaVerification) {
        return authingService.sendCode(token, account, channel, verifyCaptcha(captchaVerification));
    }

    @AuthingUserToken
    @RequestMapping(value = "/sendcode/unbind", method = RequestMethod.GET)
    public ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest,
                                         HttpServletResponse servletResponse) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        String captchaVerification = servletRequest.getParameter("captchaVerification");
        return service.sendCodeUnbind(servletRequest, servletResponse, verifyCaptcha(captchaVerification));
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/account", method = RequestMethod.GET)
    public ResponseEntity updateAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse,
                                        @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.updateAccount(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unbind/account", method = RequestMethod.GET)
    public ResponseEntity unbindAccount(HttpServletRequest servletRequest,
                                        HttpServletResponse servletResponse,
                                        @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.unbindAccount(servletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/bind/account", method = RequestMethod.GET)
    public ResponseEntity bindAccount(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse,
                                      @CookieValue(value = "_Y_G_", required = false) String token) {
        UserCenterServiceInter service = getServiceImpl(servletRequest);
        return service.bindAccount(servletRequest, servletResponse, token);
    }


    @AuthingUserToken
    @RequestMapping(value = "/conn/list", method = RequestMethod.GET)
    public ResponseEntity linkConnList(@CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.linkConnList(token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/link/account", method = RequestMethod.GET)
    public ResponseEntity linkAccount(@CookieValue(value = "_Y_G_", required = false) String token,
                                      @RequestParam(value = "secondtoken") String secondtoken) {
        return authingService.linkAccount(token, secondtoken);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unlink/account", method = RequestMethod.GET)
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
