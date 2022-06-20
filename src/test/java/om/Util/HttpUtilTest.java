package om.Util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Utils.EsQueryUtils;
import com.om.Utils.HttpClientUtils;
import com.om.omwebserver.OmWebserverApplication;
import org.elasticsearch.client.RestHighLevelClient;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Objects;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = OmWebserverApplication.class)
public class HttpUtilTest {

    @Autowired
    Environment env;

    ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void EsQueryUtils() {
        try {
            String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
            String host = env.getProperty("es.host");
            int port = Integer.parseInt(env.getProperty("es.port", "9200"));
            String scheme = env.getProperty("es.scheme");
            String esUser = userpass[0];
            String password = userpass[1];
            RestHighLevelClient client = HttpClientUtils.restClient(host, port, scheme, esUser, password);
            EsQueryUtils esQueryUtils = new EsQueryUtils();
            String s = esQueryUtils.esScroll(client, "test", "testindex");
            JsonNode jsonNode = objectMapper.readTree(s);

            Assert.assertEquals(jsonNode.get("code").intValue(), 200);
            Assert.assertTrue(jsonNode.get("totalCount").intValue() >= 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
