package om.Controller;

import com.om.Controller.QueryController;
import com.om.Dao.QueryDao;
import com.om.Service.QueryService;
import com.om.omwebserver.OmWebserverApplication;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@RunWith(SpringRunner.class)
@SpringBootTest(classes = OmWebserverApplication.class)
public class ControllerTest {

    @Autowired
    QueryController qc;

    private MockMvc mvc;
    private MockHttpSession session;

    @BeforeAll
    public void setupMockMvc() {
        mvc = MockMvcBuilders.standaloneSetup(qc).build(); //初始化MockMvc对象
        session = new MockHttpSession();
    }

    @Test
    public void queryCompanyContributors() {
        try {
            mvc.perform(MockMvcRequestBuilders.get("/query/company/contribute")
                    .session(session)
                    .contentType(MediaType.APPLICATION_JSON_UTF8)
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .param("community", "openeuler")
                    .param("contributeType", "pr")
                    .param("timeRange", "all"))
                    .andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.code").value("200"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.data").isArray())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.msg").value("success"))
                    .andDo(MockMvcResultHandlers.print());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void sigDetails() {
        try {
            String body = "{\"community\":\"openeuler\",\"sigs\": [\"xxxx\"]}";
            ResultActions perform = mvc.perform(MockMvcRequestBuilders.post("/query/sigDetails")
                    .session(session)
                    .contentType(MediaType.APPLICATION_JSON_UTF8)
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .content(body));

            perform.andExpect(MockMvcResultMatchers.status().isOk())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.code").value("200"))
                    .andExpect(MockMvcResultMatchers.jsonPath("$.data").isEmpty())
                    .andExpect(MockMvcResultMatchers.jsonPath("$.msg").value("success"))
                    .andDo(MockMvcResultHandlers.print());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
