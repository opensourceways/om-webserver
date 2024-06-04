/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package om.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.omwebserver.OmWebserverApplication;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = OmWebserverApplication.class)
public class ServiceTest {
    @Autowired
    private com.om.Service.AuthingService AuthingService;

    ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void authingUserPermission() {
        try {
//            ResponseEntity res1 = AuthingService.authingUserPermission("openeuler", "884", "sigRead", null);
//            ResponseEntity res2 = AuthingService.authingUserPermission("openeuler", "84", "sigRead", null);
//            ResponseEntity res3 = AuthingService.authingUserPermission("openeuler", "83", "sigRead", null);
//
//            Assert.assertEquals(res1.getStatusCodeValue(), 401);
//            Assert.assertEquals(res2.getStatusCodeValue(), 401);
//            Assert.assertEquals(res3.getStatusCodeValue(), 401);

//            JsonNode jsonNode1 = objectMapper.readTree(objectMapper.writeValueAsString(res1.getBody()));
//            JsonNode jsonNode3 = objectMapper.readTree(objectMapper.writeValueAsString(res3.getBody()));
//
//            Assert.assertEquals(jsonNode1.get("data").get("permissions").size(), 0);
//            Assert.assertEquals(jsonNode3.get("data").get("permissions").size(), 1);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}