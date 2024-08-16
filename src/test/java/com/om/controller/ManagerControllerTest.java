package com.om.controller;

import com.anji.captcha.model.common.RepCodeEnum;
import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.om.service.OneIdManageService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.HashMap;
import java.util.Map;


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
public class ManagerControllerTest {
    @MockBean
    private OneIdManageService MockOneIdManageService;

    @MockBean
    private CaptchaService mockCaptchaService;

    @Test
    public void testSendCode() throws Exception {
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(MockOneIdManageService.sendCode(any(), any(), any(Boolean.class)))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        Map<String, String> map = new HashMap<>();
        map.put("account", "account");
        map.put("channel", "channel");
        ResponseEntity response = MockOneIdManageService.sendCode(map, "token", Boolean.TRUE);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testBindAccount() throws Exception {
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(MockOneIdManageService.bindAccount(any(), any(), any()))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResponseEntity response = MockOneIdManageService.bindAccount(request, new HashMap<>(), "token");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testRevokePrivacy() throws Exception {
        when(mockCaptchaService.verification(any(CaptchaVO.class))).thenReturn(new ResponseModel(RepCodeEnum.SUCCESS));
        when(MockOneIdManageService.revokePrivacy(any(), any(), any()))
                .thenReturn(new ResponseEntity<>("body", HttpStatus.OK));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity res = MockOneIdManageService.revokePrivacy( "userId", request, response);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}