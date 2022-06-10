package com.om.Controller;

import com.om.Service.AuthingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping(value = "/authing")
@RestController
public class AuthingController {
    @Autowired
    AuthingService authingService;

    @RequestMapping(value = "/user/permission")
    public ResponseEntity getUser(@RequestParam(value = "community") String community,
                                  @RequestParam(value = "userId") String userId,
                                  @RequestParam(value = "permission") String permission) {
        return authingService.authingUserPermission(community, userId, permission);
    }
}
