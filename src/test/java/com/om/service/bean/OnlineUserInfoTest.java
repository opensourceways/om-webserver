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
package com.om.service.bean;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import java.util.HashSet;
import java.util.Set;
/**
 * OnlineUserInfo测试类.
 */
class OnlineUserInfoTest {
    /**
     * idtoken测试.
     */
    @Test
    void testIdToken() {
        OnlineUserInfo onlineUserInfo = new OnlineUserInfo();
        onlineUserInfo.setIdToken("test");
        assertEquals("test", onlineUserInfo.getIdToken());
    }
    /**
     * logoutUrl测试.
     */
    @Test
    void testLogoutUrls() {
        OnlineUserInfo onlineUserInfo = new OnlineUserInfo();
        Set<String> logoutUrl = new HashSet<>();
        onlineUserInfo.setLogoutUrls(logoutUrl);
        assertEquals(logoutUrl, onlineUserInfo.getLogoutUrls());
    }
}
