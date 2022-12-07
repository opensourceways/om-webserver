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
import com.om.Service.AuthingService;
import com.om.Vo.OauthTokenVo;
import com.om.authing.AuthingUserToken;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import static com.anji.captcha.controller.CaptchaController.getRemoteId;


@RequestMapping(value = "/oneid")
@RestController
public class AuthingController {
    @Autowired
    AuthingService authingService;

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
    public ResponseEntity accountExists(@RequestParam(value = "userName", required = false) String userName,
                                        @RequestParam(value = "account", required = false) String account) {
        return authingService.accountExists(userName, account);
    }

    @RequestMapping(value = "/v3/sendCode")
    public ResponseEntity sendCodeV3(@RequestParam(value = "account") String account,
                                     @RequestParam(value = "channel") String channel,
                                     @RequestParam("captchaVerification") String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        boolean isSuccess = response.isSuccess();
        return authingService.sendCodeV3(account, channel, isSuccess);
    }

    @RequestMapping(value = "/register")
    public ResponseEntity register(@RequestParam(value = "userName") String userName,
                                   @RequestParam(value = "account") String account,
                                   @RequestParam(value = "code") String code) {
        return authingService.register(userName, account, code);
    }

    @RequestMapping(value = "/login")
    public ResponseEntity login(HttpServletRequest httpServletRequest,
                                HttpServletResponse servletResponse,
                                @RequestParam(value = "community") String community,
                                @RequestParam(value = "permission") String permission,
                                @RequestParam(value = "account") String account,
                                @RequestParam(value = "code") String code) {
        return authingService.login(httpServletRequest, servletResponse, community, permission, account, code);
    }

    @RequestMapping(value = "/app/verify")
    public ResponseEntity appVerify(@RequestParam(value = "app_id") String appId,
                                    @RequestParam(value = "redirect_uri") String redirect) {
        return authingService.appVerify(appId, redirect);
    }

    @AuthingUserToken
    @RequestMapping(value = "/oidc/authorize", method = RequestMethod.GET)
    public ResponseEntity oidcAuthorize(@CookieValue(value = "_Y_G_", required = false) String token,
                                        @RequestParam(value = "app_id") String appId,
                                        @RequestParam(value = "redirect_uri") String redirectUri,
                                        @RequestParam(value = "response_type") String responseType,
                                        @RequestParam(value = "state", required = false) String state,
                                        @RequestParam(value = "scope") String scope) {
        return authingService.oidcAuthorize(token, appId, redirectUri, responseType, state, scope);
    }

    @RequestMapping(value = "/oidc/token", method = RequestMethod.POST)
    public ResponseEntity oidcToken(@RequestParam(value = "app_id", required = false) String appId,
                                    @RequestParam(value = "app_secret", required = false) String appSecret,
                                    @RequestParam(value = "grant_type") String grantType,
                                    @RequestParam(value = "code", required = false) String code,
                                    @RequestParam(value = "state", required = false) String state,
                                    @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                    @RequestParam(value = "refresh_token", required = false) String refreshToken,
                                    @RequestBody(required = false) OauthTokenVo oauthTokenVo) {
        return authingService.oidcToken(appId, appSecret, grantType, code, state, redirectUri, oauthTokenVo, refreshToken);
    }

    @RequestMapping(value = "/oidc/user")
    public ResponseEntity oidcUser(@RequestParam(value = "access_token") String accessToken) {
        return authingService.userByAccessToken(accessToken);
    }

    @AuthingUserToken
    @RequestMapping(value = "/logout")
    public ResponseEntity logout(HttpServletRequest httpServletRequest,
                                 HttpServletResponse servletResponse,
                                 @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.logoutOld(httpServletRequest, servletResponse, token);
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
    public ResponseEntity userInfo(@CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.personalCenterUserInfo(token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/delete/user")
    public ResponseEntity deleteUser(HttpServletRequest httpServletRequest,
                                     HttpServletResponse servletResponse,
                                     @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.deleteUser(httpServletRequest, servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/sendcode")
    public ResponseEntity sendCode(@RequestParam(value = "account") String account,
                                   @RequestParam(value = "field") String field,
                                   @RequestParam(value = "account_type") String account_type) {
        return authingService.sendCode(account, account_type, field);
    }

    @AuthingUserToken
    @RequestMapping(value = "/sendcode/unbind")
    public ResponseEntity sendCodeUnbind(@RequestParam(value = "account") String account,
                                         @RequestParam(value = "account_type") String account_type) {
        return authingService.sendCodeUnbind(account, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/account")
    public ResponseEntity updateAccount(@CookieValue(value = "_Y_G_", required = false) String token,
                                        @RequestParam(value = "oldaccount") String oldaccount,
                                        @RequestParam(value = "oldcode") String oldcode,
                                        @RequestParam(value = "account") String account,
                                        @RequestParam(value = "code") String code,
                                        @RequestParam(value = "account_type") String account_type) {
        return authingService.updateAccount(token, oldaccount, oldcode, account, code, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unbind/account")
    public ResponseEntity unbindAccount(@CookieValue(value = "_Y_G_", required = false) String token,
                                        @RequestParam(value = "account") String account,
                                        @RequestParam(value = "code") String code,
                                        @RequestParam(value = "account_type") String account_type) {
        return authingService.unbindAccount(token, account, code, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/bind/account")
    public ResponseEntity bindAccount(@CookieValue(value = "_Y_G_", required = false) String token,
                                      @RequestParam(value = "account") String account,
                                      @RequestParam(value = "code") String code,
                                      @RequestParam(value = "account_type") String account_type) {
        return authingService.bindAccount(token, account, code, account_type);
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
    public ResponseEntity updateUserBaseInfo(@CookieValue(value = "_Y_G_", required = false) String token,
                                             @RequestBody Map<String, Object> map) {
        return authingService.updateUserBaseInfo(token, map);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/photo", method = RequestMethod.POST)
    public ResponseEntity upload(@CookieValue(value = "_Y_G_", required = false) String token,
                                 @RequestParam(value = "file") MultipartFile file) {
        return authingService.updatePhoto(token, file);
    }
}
