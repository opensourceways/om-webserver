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
import com.om.Service.AuthingService;
import com.om.Service.OneIdManageService;
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

@RequestMapping(value = "/oneid/manager")
@RestController
public class ManagerController {
    private static final Logger logger =  LoggerFactory.getLogger(ManagerController.class);

    @Autowired
    private CaptchaService captchaService;

    @Autowired
    private OneIdManageService oneIdManageService;

    @Autowired
    private AuthingService authingService;

    @RequestMapping(value = "/tokens", method = RequestMethod.POST)
    public ResponseEntity tokenApply(@RequestBody Map<String, String> body) {
        return oneIdManageService.tokenApply(body);
    }

    @ManageToken
    @RequestMapping(value = "/sendcode", method = RequestMethod.POST)
    public ResponseEntity sendCode(@RequestBody Map<String, String> body,
                                   @RequestHeader(value = "token") String token) {
        return oneIdManageService.sendCode(body, token, verifyCaptcha((String) body.get("captchaVerification")));
    }

    @ManageToken
    @RequestMapping(value = "/bind/account", method = RequestMethod.POST)
    public ResponseEntity bindAccount(@RequestBody Map<String, String> body,
                                      @RequestHeader(value = "token") String token) {
        return oneIdManageService.bindAccount(body, token);
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
        @RequestParam(value = "userId", required = false) String userId,
        @RequestParam(value = "giteeLogin", required = false) String giteeLogin,
        @RequestParam(value = "githubLogin", required = false) String githubLogin) {
        return oneIdManageService.getUserInfo(username, userId, giteeLogin, githubLogin);
    }

    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/u/permissions", method = RequestMethod.GET)
    public ResponseEntity getUserPermissions(
        @RequestParam("community") String community,
        @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.userPermissions(community, token);
    }

    @ManageToken
    @AuthingUserToken
    @RequestMapping(value = "/personal/center/user", method = RequestMethod.GET)
    public ResponseEntity getUserCenterInfo(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        @CookieValue(value = "_Y_G_", required = false) String token) {
        return authingService.personalCenterUserInfo(servletRequest, servletResponse, token);
    }

    private boolean verifyCaptcha(String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        if (response != null) {
            logger.info("captcha response msg: " + response.getRepMsg() + "  " +
                        "captcha response status: " + response.isSuccess());
            return response.isSuccess();
        }
        return false;
    }
}