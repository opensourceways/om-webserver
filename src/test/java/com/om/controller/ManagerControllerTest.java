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
import com.alibaba.fastjson2.JSONObject;
import com.om.omwebserver.OmWebserverApplication;
import com.om.service.OneIdManageService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = OmWebserverApplication.class)
@AutoConfigureMockMvc
@WebAppConfiguration
public class ManagerControllerTest extends AbstractJUnit4SpringContextTests {
    @Autowired
    private WebApplicationContext webApplicationContext;

    /**
     * 用于注入 OneId 管理服务的对象.
     */
    @Autowired
    private OneIdManageService oneIdManageService;

    private MockMvc mockMvc;
    @Before
    public void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    /**
     * 测试1个参数.
     * @throws Exception exception.
     */
    @Test
    public void test_single_param() throws Exception {
        // 测试用户名
        LinkedMultiValueMap<String, String> paramMap = new LinkedMultiValueMap<>();
        paramMap.add("username", "");
        checkResult(paramMap);

        // 测试用户id
        paramMap = new LinkedMultiValueMap<>();
        paramMap.add("userId", "");
        checkResult(paramMap);

        // 测试gitee Login
        paramMap = new LinkedMultiValueMap<>();
        paramMap.add("giteeLogin", "");
        checkResult(paramMap);

        // 测试github Login
        paramMap = new LinkedMultiValueMap<>();
        paramMap.add("githubLogin", "");
        checkResult(paramMap);

        // 测试手机号码
        paramMap = new LinkedMultiValueMap<>();
        paramMap.add("phone", "");
        checkResult(paramMap);

        // 测试邮箱
        paramMap = new LinkedMultiValueMap<>();
        paramMap.add("email", "");
        checkResult(paramMap);
    }

    /**
     * 测试不只1个参数.
     * @throws Exception exception.
     */
    @Test
    public void test_not_single_param() throws Exception {
        String errMsg = "{\"msg\":{\"code\":\"E00064\",\"message_en\":\"Only ID, username, gitee username, github username, phone and email are supported for single parameter search of users\",\"message_zh\":\"仅支持ID、用户名、gitee用户名、github用户、电话号码、邮箱名单一参数查找用户\"},\"code\":400}";
        LinkedMultiValueMap<String, String> paramMap = new LinkedMultiValueMap<>();
        paramMap.add("username", "gi1tee");
        paramMap.add("userId", "65129");
        String content = mockMvc.perform(MockMvcRequestBuilders.get("/oneid/manager/getuserinfo")
                        .params(paramMap)
                        .accept(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertEquals(content,errMsg);
    }

    private void checkResult(LinkedMultiValueMap<String, String> paramMap) throws Exception {
        String content = mockMvc.perform(MockMvcRequestBuilders.get("/oneid/manager/getuserinfo")
                        .params(paramMap)
                        .accept(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        JSONObject res = JSON.parseObject(content);
        JSONObject data = res.getJSONObject("data");
        assertTrue(data.containsKey("id"));
    }
}
