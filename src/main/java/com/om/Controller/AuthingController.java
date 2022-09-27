package com.om.Controller;

import com.om.Service.AuthingService;
import com.om.authing.AuthingUserToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RequestMapping(value = "/authing")
@RestController
public class AuthingController {
    @Autowired
    AuthingService authingService;

    @AuthingUserToken
    @RequestMapping(value = "/logout")
    public ResponseEntity logout(@RequestHeader("token") String token) {
        return authingService.logout(token);
    }

    @AuthingUserToken
    @RequestMapping(value = "/user/permission")
    public ResponseEntity getUser(@RequestParam(value = "community") String community,
                                  @RequestHeader("token") String token) {
        return authingService.authingUserPermission(community, token);
    }

    @RequestMapping(value = "/token/apply")
    public ResponseEntity tokenApply(@RequestParam(value = "community") String community,
                                     @RequestParam(value = "code") String code,
                                     @RequestParam(value = "permission") String permission,
                                     @RequestParam(value = "redirect") String redirect) {
        return authingService.tokenApply(community, code, permission, redirect);
    }

    @AuthingUserToken
    @RequestMapping(value = "/personal/center/user")
    public ResponseEntity userInfo(@RequestHeader("token") String token) {
        return authingService.personalCenterUserInfo(token);
    }

    @RequestMapping(value = "/sendcode")
    public ResponseEntity sendCode(@RequestParam(value = "account") String account,
                                   @RequestParam(value = "field") String field,
                                   @RequestParam(value = "account_type") String account_type) {
        return authingService.sendCode(account, account_type, field);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/account")
    public ResponseEntity updateAccount(@RequestHeader(value = "token") String token,
                                        @RequestParam(value = "account") String account,
                                        @RequestParam(value = "code") String code,
                                        @RequestParam(value = "account_type") String account_type) {
        return authingService.updateAccount(token, account, code, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unbind/account")
    public ResponseEntity unbindAccount(@RequestHeader(value = "token") String token,
                                        @RequestParam(value = "account_type") String account_type) {
        return authingService.unbindAccount(token, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/bind/account")
    public ResponseEntity bindAccount(@RequestHeader(value = "token") String token,
                                      @RequestParam(value = "account") String account,
                                      @RequestParam(value = "code") String code,
                                      @RequestParam(value = "account_type") String account_type) {
        return authingService.bindAccount(token, account, code, account_type);
    }

    @AuthingUserToken
    @RequestMapping(value = "/link/account")
    public ResponseEntity linkAccount(@RequestHeader(value = "token") String token,
                                      @RequestParam(value = "secondtoken") String secondtoken) {
        return authingService.linkAccount(token, secondtoken);
    }

    @AuthingUserToken
    @RequestMapping(value = "/unlink/account")
    public ResponseEntity unLinkAccount(@RequestHeader(value = "token") String token,
                                        @RequestParam(value = "platform") String platform) {
        return authingService.unLinkAccount(token, platform);
    }

    @AuthingUserToken
    @RequestMapping(value = "/update/baseInfo")
    public ResponseEntity updateUserBaseInfo(@RequestHeader(value = "token") String token,
                                             @RequestParam(value = "item") String item,
                                             @RequestParam(value = "input") String input) {
        return authingService.updateUserBaseInfo(token, item, input);
    }

    @RequestMapping(value = "/update/photo", method = RequestMethod.POST)
    public ResponseEntity upload(@RequestHeader(value = "token") String token,
                                 @RequestParam(value = "file") MultipartFile file) {
        return authingService.updatePhoto(token, file);
    }
}
