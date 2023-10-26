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
import com.om.Service.OneIdManageService;
import com.om.token.ManageToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequestMapping(value = "/oneid/manager")
@RestController
public class OneIdManageController {
    private static final Logger logger =  LoggerFactory.getLogger(OneIdManageController.class);

    @Autowired
    OneIdManageService oneIdManageService;

    @Autowired
    CaptchaService captchaService;

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity tokenApply(@RequestBody Map<String, String> body) {
        return oneIdManageService.tokenApply(body);
    }
    
    @ManageToken
    @RequestMapping(value = "/sendcode", method = RequestMethod.POST)
    public ResponseEntity sendCode(@RequestBody Map<String, String> body,
                                   @RequestHeader(value = "token") String token) {
        verifyCaptcha((String) body.get("captchaVerification"));                            
        return oneIdManageService.sendCode(body, token, verifyCaptcha(body.get("captchaVerification")));
    }

    @ManageToken
    @RequestMapping(value = "/bind/account", method = RequestMethod.POST)
    public ResponseEntity bindAccount(@RequestBody Map<String, String> body,
                                      @RequestHeader(value = "token") String token) {
        return oneIdManageService.bindAccount(body, token);
    }

    private boolean verifyCaptcha(String captchaVerification) {
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaVerification(captchaVerification);
        ResponseModel response = captchaService.verification(captchaVO);
        logger.info("captchaVerification: " + captchaVerification);
        if (response != null) {
            logger.info(response.getRepMsg());
            return response.isSuccess();
        }
        return false;
    }
}
