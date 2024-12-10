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

package com.om.Service;

import cn.authing.core.types.Application;
import cn.authing.core.types.ApplicationPermissionStrategyConfig;
import cn.authing.core.types.ApplicationQRCodeScanning;
import cn.authing.core.types.ISsoPageCustomizationSettings;
import com.om.Dao.AuthingManagerDao;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.RedisDao;
import com.om.Modules.ServerErrorException;
import com.om.Modules.authing.AuthingAppSync;
import com.om.Utils.AuthingUtil;
import com.om.Utils.LimitUtil;
import com.om.token.ClientSessionManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthingServiceTest {
    @InjectMocks
    private AuthingService authingService;

    @Mock
    private AuthingUtil authingUtil;

    @Mock
    private Environment env;

    @Mock
    private AuthingUserDao authingUserDao;

    @Mock
    private RedisDao redisDao;

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private LimitUtil limitUtil;

    @Mock
    private JwtTokenCreateService jwtTokenCreateService;

    @Mock
    private AuthingAppSync authingAppSync;

    @Mock
    private ClientSessionManager clientSessionManager;

    @Mock
    private AuthingManagerDao authingManagerDao;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(authingService, "authingUserDao", authingUserDao);
        ReflectionTestUtils.setField(authingService, "env", env);
        authingService.init();
    }

    @Test
    public void testAccountExists_AppDoesNotExist() throws ServerErrorException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter("username")).thenReturn("testuser");
        when(request.getParameter("client_id")).thenReturn("nonexistent_app");

        Application app = null; // Simulate non-existent app
        when(authingUserDao.getAppById(anyString())).thenReturn(app);

        ResponseEntity<?> result = authingService.accountExists(request, response);

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
    }

    @Test
    public void testAccountExists_UsernameBlank() throws ServerErrorException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter("username")).thenReturn("");
        when(request.getParameter("client_id")).thenReturn("existing_app");

        List<String> redirectUri = new ArrayList<>();
        List<String> logoutUri = new ArrayList<>();
        ISsoPageCustomizationSettings iSsoPageCustomizationSettings = new ISsoPageCustomizationSettings(false,
                false, false, false, false, false, false, false,
                false, false);
        ApplicationQRCodeScanning applicationQRCodeScanning = new ApplicationQRCodeScanning(false, 1);
        ApplicationPermissionStrategyConfig permissionStrategyConfig = new ApplicationPermissionStrategyConfig(false,
                "", "", "");
        Application app = new Application("4234", "324", "", false, false, false, "", "", "fdsf",
                "", "", iSsoPageCustomizationSettings, "", redirectUri, logoutUri, false, false, false,
                false, new ArrayList<>(), "", new ArrayList<>(), "",
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                false, new ArrayList<>(), new ArrayList<>(), "",
                applicationQRCodeScanning, new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                false, permissionStrategyConfig, false);
        when(authingUserDao.getAppById(anyString())).thenReturn(app);

        ResponseEntity<?> result = authingService.accountExists(request, response);

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
    }

    @Test
    public void testAccountExists_UserAlreadyExists() throws ServerErrorException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter("username")).thenReturn("existing_user");
        when(request.getParameter("client_id")).thenReturn("existing_app");

        List<String> redirectUri = new ArrayList<>();
        List<String> logoutUri = new ArrayList<>();
        ISsoPageCustomizationSettings iSsoPageCustomizationSettings = new ISsoPageCustomizationSettings(false,
                false, false, false, false, false, false, false,
                false, false);
        ApplicationQRCodeScanning applicationQRCodeScanning = new ApplicationQRCodeScanning(false, 1);
        ApplicationPermissionStrategyConfig permissionStrategyConfig = new ApplicationPermissionStrategyConfig(false,
                "", "", "");
        Application app = new Application("4234", "324", "", false, false, false, "", "", "fdsf",
                "", "", iSsoPageCustomizationSettings, "", redirectUri, logoutUri, false, false, false,
                false, new ArrayList<>(), "", new ArrayList<>(), "",
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                false, new ArrayList<>(), new ArrayList<>(), "",
                applicationQRCodeScanning, new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                false, permissionStrategyConfig, false);
        when(authingUserDao.getAppById(anyString())).thenReturn(app);

        boolean userExists = true; // Simulate user already exists
        when(authingUserDao.isUserExists(anyString(), anyString(), anyString())).thenReturn(userExists);

        ResponseEntity<?> result = authingService.accountExists(request, response);

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
    }

    @Test
    public void testAccountExists_Success() throws ServerErrorException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter("username")).thenReturn("new_user");
        when(request.getParameter("client_id")).thenReturn("existing_app");

        List<String> redirectUri = new ArrayList<>();
        List<String> logoutUri = new ArrayList<>();
        ISsoPageCustomizationSettings iSsoPageCustomizationSettings = new ISsoPageCustomizationSettings(false,
                false, false, false, false, false, false, false,
                false, false);
        ApplicationQRCodeScanning applicationQRCodeScanning = new ApplicationQRCodeScanning(false, 1);
        ApplicationPermissionStrategyConfig permissionStrategyConfig = new ApplicationPermissionStrategyConfig(false,
                "", "", "");
        Application app = new Application("4234", "324", "", false, false, false, "", "", "fdsf",
                "", "", iSsoPageCustomizationSettings, "", redirectUri, logoutUri, false, false, false,
                false, new ArrayList<>(), "", new ArrayList<>(), "",
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                false, new ArrayList<>(), new ArrayList<>(), "",
                applicationQRCodeScanning, new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
                false, permissionStrategyConfig, false);
        when(authingUserDao.getAppById(anyString())).thenReturn(app);

        boolean userExists = false; // Simulate user does not exist
        when(authingUserDao.isUserExists(anyString(), anyString(), anyString())).thenReturn(userExists);

        ResponseEntity<?> result = authingService.accountExists(request, response);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals("success", ((Map<?, ?>) result.getBody()).get("msg"));
    }
}