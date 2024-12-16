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
import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;
/**
 * CommonAPIController 测试用例.
 */
public class CommonAPIControllerTest {
    /**
     * CommonAPIController实例.
     */
    private CommonAPIController commonAPIController = new CommonAPIController();
    /**
     * 检查服务健康状态.
     */
    @Test
    public void checkOmService() {
        assertThat(commonAPIController.checkOmService()).isEqualTo("normal");
    }
    /**
     * 获取隐私协议.
     */
    @Test
    public void getPrivacyVersion() {
        ReflectionTestUtils.setField(commonAPIController, "oneidPrivacyVersion", "20240815");
        ResponseEntity response = commonAPIController.getPrivacyVersion();
        Object responseBody = response.getBody();
        if (!(responseBody instanceof Map)) {
            Assert.fail();
        }
        Map<String, Object> resMap = (Map<String, Object>) responseBody;
        if (!resMap.containsKey("data")) {
            Assert.fail();
        }
        Map<String, String> dataMap = (Map<String, String>) resMap.get("data");
        assertThat(dataMap.get("oneidPrivacyAccepted")).isEqualTo("20240815");
    }
}
