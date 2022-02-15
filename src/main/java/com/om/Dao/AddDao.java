package com.om.Dao;


import com.om.Modules.openEuler;
import com.om.Utils.AsyncHttpUtil;
import com.om.Utils.HttpClientUtils;
import com.om.Vo.BugQuestionnaireVo;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;

import static com.om.Dao.QueryDao.objectMapper;

@Repository
public class AddDao {

    @Autowired
    AsyncHttpUtil asyncHttpUtil;

    @Value("${esurl}")
    String url;

    @Autowired
    private Environment env;

    @Autowired
    protected openEuler openEuler;


    public String putBugQuestionnaire(String community, String item, BugQuestionnaireVo bugQuestionnaireVo) {
        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        String res = null;
        String indexName = null;

        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getBug_questionnaire_index();
                indexName = indexName.substring(1);
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        LocalDateTime now = LocalDateTime.now();
        String nowStr = now.toString().split("\\.")[0] + "+08:00";
        bugQuestionnaireVo.setFillTime(nowStr);


        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        BulkRequest request = new BulkRequest();
        Map resMap = objectMapper.convertValue(bugQuestionnaireVo, Map.class);
        request.add(new IndexRequest(indexName, "_doc").source(resMap));

        if (request.requests().size() != 0)
            try {
                BulkResponse bulk = restHighLevelClient.bulk(request, RequestOptions.DEFAULT);
                int status_code = bulk.status().getStatus();
                if (status_code == 200) {
                    res = "{\"code\":200,\"data\":{\"questionnaire_count\":\"1\"},\"msg\":\"update success\"}";
                } else {
                    res = String.format("{\"code\":%i,\"data\":{\"questionnaire_count\":\"0\"},\"msg\":\"add bug questionnaire failed\"}", status_code);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    restHighLevelClient.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        return res;
    }
}
