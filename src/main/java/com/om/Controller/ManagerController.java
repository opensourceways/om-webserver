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

import com.om.Service.OneIdManageService;
import com.om.authing.AuthingUserToken;
import com.om.token.ManageToken;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequestMapping(value = "/oneid/manager")
@RestController
public class ManagerController {
    @Autowired
    OneIdManageService oneIdManageService;

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity tokenApply(@RequestBody Map<String, String> body) {
        return oneIdManageService.tokenApply(body);
    }

    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/authenticate", method = RequestMethod.GET)
    public ResponseEntity authenticate(
        @RequestParam("community") String community,
        @CookieValue(value = "_Y_G_", required = false) String userCookie) {
        return oneIdManageService.authenticate(community, userCookie);
    }

    @ManageToken
    @RequestMapping(value = "/getuserinfo", method = RequestMethod.GET)
    public ResponseEntity getUser(
        @RequestParam(value = "username", required = false) String username,
        @RequestParam(value = "userId", required = false) String userId) {
        return oneIdManageService.getUserInfo(username, userId);
    }
    
}