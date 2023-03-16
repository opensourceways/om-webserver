package com.om.Controller;

import com.om.Service.OneIdManageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequestMapping(value = "/oneid/manager")
@RestController
public class OneIdManageController {
    @Autowired
    OneIdManageService oneIdManageService;

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity tokenApply(@RequestBody Map<String, String> body) {
        return oneIdManageService.tokenApply(body);
    }
}
