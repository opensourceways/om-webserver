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

package com.om.authing;

import com.om.dao.RedisDao;
import com.om.service.JwtTokenCreateService;
import com.om.utils.EncryptionService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.ModelAndView;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthingInterceptorTest {
    @Mock
    private RedisDao mockRedisDao;
    @Mock
    private EncryptionService mockEncryption;
    @Mock
    private JwtTokenCreateService mockJwtTokenCreateService;

    @InjectMocks
    private AuthingInterceptor authingInterceptorUnderTest;

    @BeforeEach
    public void setUp() {
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "env", new MockEnvironment());
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "authingTokenBasePassword",
                "authingTokenBasePassword");
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "rsaAuthingPrivateKey", "rsaAuthingPrivateKey");
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "cookieTokenName", "cookieTokenName");
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "verifyTokenName", "verifyTokenName");
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "allowDomains", "allowDomains");
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "cookieSecures", "cookieSecures");
        ReflectionTestUtils.setField(authingInterceptorUnderTest, "oneidPrivacyVersion", "oneidPrivacyVersion");
    }

    @Test
    public void testInit() {
        authingInterceptorUnderTest.init();
    }

    @Test
    public void testPreHandle() throws Exception {
        final MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        final MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        when(mockRedisDao.exists("key")).thenReturn(false);
        when(mockRedisDao.get("key")).thenReturn("result");
        when(mockJwtTokenCreateService.refreshAuthingUserToken(any(HttpServletRequest.class),
                any(String.class), eq("userId"), eq(Map.ofEntries()))).thenReturn(new String[]{"result"});
        when(mockRedisDao.expire("key")).thenReturn(0L);

        final boolean result = authingInterceptorUnderTest.preHandle(httpServletRequest, httpServletResponse, "object");

        assertThat(result).isTrue();
    }

    @Test
    public void testPreHandle_JwtTokenCreateServiceReturnsNoItems() throws Exception {
        final MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        final MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        when(mockRedisDao.exists("key")).thenReturn(false);
        when(mockRedisDao.get("key")).thenReturn("result");
        when(mockJwtTokenCreateService.refreshAuthingUserToken(any(HttpServletRequest.class),
                any(String.class), eq("userId"), eq(Map.ofEntries()))).thenReturn(new String[]{});
        when(mockRedisDao.expire("key")).thenReturn(0L);

        final boolean result = authingInterceptorUnderTest.preHandle(httpServletRequest, httpServletResponse, "object");

        assertThat(result).isTrue();
    }

    @Test
    public void testPostHandle() throws Exception {
        authingInterceptorUnderTest.postHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), "o",
                new ModelAndView("viewName", Map.ofEntries(Map.entry("value", "value")), HttpStatus.OK));
    }

    @Test
    public void testAfterCompletion() throws Exception {
        authingInterceptorUnderTest.afterCompletion(new MockHttpServletRequest(), new MockHttpServletResponse(), "o",
                new Exception("message"));
    }

    @Test
    public void testIsLoginNormal() throws Exception {
        Method method = authingInterceptorUnderTest.getClass().getDeclaredMethod("isLoginNormal",
                String.class, String.class);
        method.setAccessible(true);
        when(mockRedisDao.containListValue(any(), any())).thenReturn(true);
        method.invoke(authingInterceptorUnderTest, "verifyToken", "userId");

    }

    @Test
    public void testRefreshAuthingUserToken() throws Exception {
        when(mockJwtTokenCreateService.authingUserToken(
                any(),any(),any(),any(),any(),any(),any())).thenReturn(new String[2]);
        mockJwtTokenCreateService.refreshAuthingUserToken( new MockHttpServletRequest(),"idToken",
                "userId", new HashMap<>());
    }
}
