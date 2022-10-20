package com.om.Controller;

import com.om.Service.AuthingService;
import com.om.authing.AuthingUserToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RequestMapping(value = "/authing")
@RestController
public class AuthingController {
    @Autowired
    AuthingService authingService;

    @AuthingUserToken
    @RequestMapping(value = "/logout")
    public ResponseEntity logout(HttpServletResponse servletResponse, @CookieValue("_Y_G_") String token) {
        return authingService.logout(servletResponse, token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/permission")
    public ResponseEntity getUser(@RequestParam(value = "community") String community,
                                  @CookieValue("_Y_G_") String token) {
        return authingService.authingUserPermission(community, token);
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
    public ResponseEntity userInfo(@CookieValue("_Y_G_") String token) {
        return authingService.personalCenterUserInfo(token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/delete/user")
    public ResponseEntity deleteUser(@CookieValue("_Y_G_") String token) {
        return authingService.deleteUser(token);
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
    public ResponseEntity updateAccount(@CookieValue(value = "_Y_G_") String token,
                                        @RequestParam(value = "oldaccount") String oldaccount,
                                        @RequestParam(value = "oldcode") String oldcode,
                                        @RequestParam(value = "account") String account,
                                        @RequestParam(value = "code") String code,
                                        @RequestParam(value = "account_type") String account_type) {
        return authingService.updateAccount(token, oldaccount, oldcode, account, code, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unbind/account")
    public ResponseEntity unbindAccount(@CookieValue(value = "_Y_G_") String token,
                                        @RequestParam(value = "account") String account,
                                        @RequestParam(value = "code") String code,
                                        @RequestParam(value = "account_type") String account_type) {
        return authingService.unbindAccount(token, account, code, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/bind/account")
    public ResponseEntity bindAccount(@CookieValue(value = "_Y_G_") String token,
                                      @RequestParam(value = "account") String account,
                                      @RequestParam(value = "code") String code,
                                      @RequestParam(value = "account_type") String account_type) {
        return authingService.bindAccount(token, account, code, account_type);
    }


    @AuthingUserToken
    @RequestMapping(value = "/conn/list")
    public ResponseEntity linkConnList(@CookieValue(value = "_Y_G_") String token) {
        return authingService.linkConnList(token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/link/account")
    public ResponseEntity linkAccount(@CookieValue(value = "_Y_G_") String token,
                                      @RequestParam(value = "secondtoken") String secondtoken) {
        return authingService.linkAccount(token, secondtoken);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unlink/account")
    public ResponseEntity unLinkAccount(@CookieValue(value = "_Y_G_") String token,
                                        @RequestParam(value = "platform") String platform) {
        return authingService.unLinkAccount(token, platform);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/baseInfo", method = RequestMethod.POST)
    public ResponseEntity updateUserBaseInfo(@CookieValue(value = "_Y_G_") String token,
                                             @RequestBody Map<String, Object> map) {
        return authingService.updateUserBaseInfo(token, map);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/photo", method = RequestMethod.POST)
    public ResponseEntity upload(@CookieValue(value = "_Y_G_") String token,
                                 @RequestParam(value = "file") MultipartFile file) {
        return authingService.updatePhoto(token, file);
    }
}
