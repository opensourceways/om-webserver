package om.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.openEuler;
import com.om.Service.AuthingService;
import com.om.Service.QueryService;
import com.om.omwebserver.OmWebserverApplication;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = OmWebserverApplication.class)
public class ServiceTest {

    @Autowired
    private QueryService queryService;

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

    @Test
    public void queryAll() {
        try {
            String res = queryService.queryAll("openeuler");
            JsonNode jsonNode = objectMapper.readTree(res);

            Assert.assertEquals(jsonNode.get("code").intValue(), 200);
            Assert.assertNotEquals(jsonNode.get("data").get("contributors").textValue(), "0");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void queryCompanyContributors() {
        try {
            String res = queryService.queryCompanyContributors("openeuler", "companyContribute", "pr", "all", null);
            JsonNode jsonNode = objectMapper.readTree(res);

            Assert.assertEquals(jsonNode.get("code").intValue(), 200);
            Assert.assertTrue(jsonNode.get("data").size() > 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}