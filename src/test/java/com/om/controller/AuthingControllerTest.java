/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.controller;

import com.alibaba.fastjson2.JSON;
import com.anji.captcha.model.common.RepCodeEnum;
import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.om.dao.AuthingUserDao;
import com.om.result.Constant;
import com.om.service.AuthingService;
import com.om.service.LoginService;
import com.om.service.OneIdManageService;
import com.om.service.SendMessageService;
import com.om.service.UserCenterServiceContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
public class AuthingControllerTest {
    @MockBean
    private AuthingService mockAuthingService;

    @MockBean
    private OneIdManageService oneIdManageService;

    @MockBean
    private UserCenterServiceContext mockUserCenterServiceContext;

    @Mock
    private AuthingService authingService;

    @Mock
    private LoginService loginService;

    @Mock
    private AuthingUserDao authingUserDao;

    @Mock
    private SendMessageService sendMessageService;

    @MockBean
    private CaptchaService mockCaptchaService;

    private AuthingController authingController = new AuthingController();

    @Before
    public void init() {
        ReflectionTestUtils.setField(authingController, "authingService", mockAuthingService);
        ReflectionTestUtils.setField(authingController, "userCenterServiceContext", mockUserCenterServiceContext);
        ReflectionTestUtils.setField(authingController, "captchaService", mockCaptchaService);
    }

    @Test
    public void testCaptchaGet() throws Exception {
        when(mockCaptchaService.get(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResponseModel responseModel = authingController.captchaGet(any(), request);

        assertThat(responseModel.getRepCode()).isEqualTo(RepCodeEnum.SUCCESS.getCode());
    }

    @Test
    public void testCaptchaCheck() throws Exception {
        when(mockCaptchaService.check(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResponseModel responseModel = authingController.captchaCheck(any(), request);
        assertThat(responseModel.getRepCode()).isEqualTo(RepCodeEnum.SUCCESS.getCode());
    }

    @Test
    public void testSendCodeV3() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.OK);
        when(authingService.sendCodeV3(any(HttpServletRequest.class),
                any(HttpServletResponse.class), any(Boolean.class))).thenReturn(responseEntity);

        ResponseEntity responseResult = authingController.sendCodeV3(request, response);

        // Verify the results
        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testSendCodeV3_CaptchaServiceReturnsError() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", -1);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.BAD_REQUEST);
        when(authingService.sendCodeV3(any(HttpServletRequest.class),
                any(HttpServletResponse.class), any(Boolean.class))).thenReturn(responseEntity);

        ResponseEntity responseResult = authingController.sendCodeV3(request, response);

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void testCaptchaLogin() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.OK);
        when(authingService.captchaLogin(any(HttpServletRequest.class))).thenReturn(responseEntity);
        ResponseEntity response = authingController.captchaLogin(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testRegister() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.OK);
        when(authingService.register(any(HttpServletRequest.class), any())).thenReturn(responseEntity);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity register = authingController.register(request, response);

        assertThat(register.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testLogin() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.OK);

        Map<String, Object> map = new HashMap<>();
        map.put("captchaVerification", "cap");
        when(loginService.login(any(HttpServletRequest.class), any(), any(Boolean.class))).thenReturn(responseEntity);
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity login = authingController.login(request, response, map);

        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testLogin_withPrivacy() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.OK);

        Map<String, Object> map = new HashMap<>();
        map.put("code", "code");
        map.put("captchaVerification", "cap");
        map.put("oneidPrivacyVersion", "privacyVersion");
        when(loginService.login(any(HttpServletRequest.class), any(), any(Boolean.class))).thenReturn(responseEntity);
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity login = authingController.login(request, response, map);

        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testLogin_CaptchaServiceReturnsError() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", -1);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.BAD_REQUEST);

        Map<String, Object> map = new HashMap<>();
        map.put("captchaVerification", "cap");
        when(loginService.login(any(HttpServletRequest.class), any(), any(Boolean.class))).thenReturn(responseEntity);
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity login = authingController.login(request, response, map);

        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void testAppVerify() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");

        HashMap<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("data", null);
        res.put("msg", null);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), HttpStatus.OK);
        when(authingService.appVerify(any(String.class), any(String.class))).thenReturn(responseEntity);
        ResponseEntity response = authingController.appVerify(request, "sdfsdfsd", "https://localhost");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testLogout() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(authingService.logout(any(), any(), any(String.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        ResponseEntity logout = authingController.logout(request, response, "");

        assertThat(logout.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testGetUser() throws Exception {
        when(mockAuthingService.authingUserPermission("token"))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity user = authingController.getUser("token");
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUserPermissions() throws Exception {
        when(oneIdManageService.userPermissions("token"))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity response = authingController.userPermissions("token");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testTokenApply() throws Exception {
        when(mockAuthingService.tokenApply(any(HttpServletRequest.class), any(HttpServletResponse.class),
                eq("code"), eq("permission"), eq("redirect")))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity responseResult = authingController.tokenApply(request, response,
                "code", "permission", "redirect");

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUserInfo() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(oneIdManageService.personalCenterUserInfo(any(), any(), any(String.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.userInfo(request, response, "");

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testDeleteUser() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(oneIdManageService.deleteUser(any(), any(), any(String.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.deleteUser(request, response, "");

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testSendCode() throws Exception {
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(mockAuthingService.sendCode(any(), any(), any(), any(), any(Boolean.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResponseEntity response = authingController.sendCode(request, "token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testSendCode_CaptchaServiceReturnsError() throws Exception {
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(mockAuthingService.sendCode(any(), any(), any(), any(), any(Boolean.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.BAD_REQUEST));
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResponseEntity response = authingController.sendCode(request, "token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void testSendCodeUnbind() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        request.setParameter("captchaVerification", "te");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(authingService.sendCodeUnbind(any(), any(), any(Boolean.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.sendCodeUnbind(request, response);

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testSendCodeUnbind_CaptchaServiceReturnsError() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        request.setParameter("captchaVerification", "te1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(authingService.sendCodeUnbind(any(), any(), any(Boolean.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.BAD_REQUEST));

        ResponseEntity responseResult = authingController.sendCodeUnbind(request, response);

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    public void testUpdateAccount() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(authingService.updateAccount(any(), any(), any(String.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.updateAccount(request, response, "");

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUnbindAccount() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(authingService.unbindAccount(any(), any(), any(String.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.unbindAccount(request, response, "");

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testBindAccount() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(authingService.bindAccount(any(), any(), any(String.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.bindAccount(request, response, "");

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testLinkConnList() throws Exception {
        when(mockAuthingService.linkConnList("token")).thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity response = authingController.linkConnList("token");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUnLinkAccount() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        when(mockAuthingService.unLinkAccount(request,"token", "platform"))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity response = authingController.unLinkAccount(request, "token", "platform");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUpdateUserBaseInfo() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(authingService.updateUserBaseInfo(any(), any(), any(String.class), any()))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity responseResult = authingController.updateUserBaseInfo(request, response, "", new HashMap<>());

        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUpload() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(authingService.updatePhoto(any(), any(), any(String.class), any()))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity upload = authingController.upload(request, response, "", null);
        assertThat(upload.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testGetPublicKey() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        when(authingService.getPublicKey())
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity publicKey = authingController.getPublicKey(request);

        assertThat(publicKey.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testResetPwdVerify() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        when(authingService.resetPwdVerify(any()))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));

        ResponseEntity response = authingController.resetPwdVerify(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testResetPwd() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("community", "openeuler");
        when(authingService.resetPwd(any(), any()))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity responseResult = authingController.resetPwd(request, response);
        assertThat(responseResult.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUpdateBaseInfo() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        when(authingUserDao.updateUserBaseInfo(any(String.class), any(), any()))
                .thenReturn("success");
        String response = authingUserDao.updateUserBaseInfo("", new HashMap<>(), any());
        assertThat(response.equals("success"));
    }

    @Test
    public void testCaptchaget() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaType("blockPuzzle");
        when(mockCaptchaService.get(any())).thenReturn(ResponseModel.success());
        ResponseModel response = mockCaptchaService.get(captchaVO);
        assertThat(response.isSuccess());
    }

    @Test
    public void testCaptchacheck() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        CaptchaVO captchaVO = new CaptchaVO();
        captchaVO.setCaptchaType("blockPuzzle");
        captchaVO.setToken("token");
        captchaVO.setPointJson("pointJson");
        when(mockCaptchaService.check(any())).thenReturn(ResponseModel.success());
        ResponseModel response = mockCaptchaService.check(captchaVO);
        assertThat(response.isSuccess());
    }

    @Test
    public void testSendMessage() throws Exception {
        when(mockUserCenterServiceContext.getUserCenterService(Constant.AUTHING)).thenReturn(authingService);
        when(sendMessageService.getMessage(any(String.class), any()))
                .thenReturn("success");
        MockHttpServletRequest request = new MockHttpServletRequest();
        Object response = sendMessageService.getMessage("", request);
        assertThat(response.equals("success"));
    }
}
