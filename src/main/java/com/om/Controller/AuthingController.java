package com.om.Controller;

import com.om.Service.AuthingService;
import com.om.authing.AuthingUserToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity userInfo(@RequestParam(value = "community") String community,
                                   @RequestHeader("token") String token) {
        return authingService.personalCenterUserInfo(community, token);
    }
}
