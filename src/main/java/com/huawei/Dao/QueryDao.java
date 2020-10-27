package com.huawei.Dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.Utils.AsyncHttpUtil;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.ListenableFuture;
import org.asynchttpclient.RequestBuilder;
import org.asynchttpclient.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author zhxia
 * @date 2020/10/22 12:00
 */
@Repository
public class QueryDao {
    static final String url="";
    @Autowired
    AsyncHttpUtil clientUtils=new AsyncHttpUtil();

static ObjectMapper objectMapper=new ObjectMapper();
    //openeuler openlookeng opengauss 测试通过
    public String queryContributors(String community) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = clientUtils.getClient();
        RequestBuilder builder = clientUtils.getBuilder();
        String index="";
        String queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"is_gitee_fork:1 OR is_gitee_issue:1 OR is_gitee_issue_comment:1 OR is_gitee_pull_request:1 OR is_gitee_review_comment:1 OR is_gitee_comment:1\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"500d\",\"field\":\"created_at\",\"min_doc_count\":0,\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"user_login.keyword\"}}}}}}";
        switch (community){
            case "openEuler":
                index="/gitee_openeuler_all_20200519_2";
                break;
            case "openGauss":
                index="/gitee_opengauss_all_20200513";
                break;
            case "openLookeng":
                index="/gitee_openlookeng_all_20200806";
                break;
            case "mindSpore":
                index="/gitee_test_mindspore_all_20200511";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"!user_login:\\\"mindspore_ci\\\" AND (is_gitee_fork:1 OR is_gitee_issue:1 OR is_gitee_issue_comment:1 OR is_gitee_pull_request:1 OR is_gitee_review_comment:1 OR is_gitee_comment:1)\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"10000d\",\"field\":\"created_at\",\"min_doc_count\":0,\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"user_login.keyword\"}}}}}}";
                break;
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode  dataNode= objectMapper.readTree(responseBody);
        int count=0;
        for (JsonNode jsonNode : dataNode.get("aggregations").get("datamap").get("buckets")) {
            count+=jsonNode.get("data").get("value").asInt();
        }
        return count+"";
    }

//测试通过
    public String querySigs(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = clientUtils.getClient();
        RequestBuilder builder = clientUtils.getBuilder();
        String index="";
        String queryjson="{\"size\":0,\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"sig_name.keyword\"}}}}";
        switch (community){
            case "openEuler":
                index="/openeuler_sigs_committers_20200901";
                break;
            case "openGauss":
                index="/opengauss_sig_20200716";
                break;
            case "openLookeng":
                index="/openlookeng_sig_20200813";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"!sig_name:\\\"sig-dpdk\\\"\"}}]}},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"sig_name.keyword\"}}}}";
                break;
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode  dataNode= objectMapper.readTree(responseBody);
        String result = dataNode.get("aggregations").get("data").get("value").toString();
        return result;
    }
//测试通过
    public String queryUsers( String community) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = clientUtils.getClient();
        RequestBuilder builder = clientUtils.getBuilder();
        String index="";
        String queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"*\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"600d\",\"field\":\"created_at\",\"min_doc_count\":0,\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"ip.keyword\"}}}}}}";
        switch (community){
            case "openEuler":
                index="/openeuler_download_20200824";
                break;
            case "openGauss":
                index="/opengauss_obs_20200708";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"!path.keyword:\\\"latest/\\\" AND !path.keyword:\\\"-\\\" AND !path.keyword:\\\"latest/x86/\\\" AND !path.keyword:\\\"latest/arm/\\\"  AND !path.keyword:\\\"1.0.0/\\\"  AND !path.keyword:\\\"1.0.0/arm/\\\"  AND !path.keyword:\\\"1.0.0/x86/\\\"   AND !path.keyword:\\\"1.0.0\\\" AND !path.keyword:\\\"1.0.0/x87\\\" AND !path.keyword:\\\"1.0.0/x86\\\" AND !path.keyword:\\\"1.0.0/x86/*\\\" AND !path.keyword:\\\"1.0.0/arm\\\" AND !path.keyword:\\\"1.0.0/openGauss-third_party_binarylibs.tar.gz/info/refs\\\"\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"1000d\",\"field\":\"created_at\",\"min_doc_count\":0,\"extended_bounds\":{\"min\":1595648542741,\"max\":1603424542741},\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"ip.keyword\"}}}}}}";
                break;
            case "openLookeng":
                index="/gitee_openlookeng_all_20200806";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"!user_login.keyword:\\\"I-am-a-robot\\\"\"}}]}},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"user_login.keyword\"}}}}";
                break;
            case "mindSpore":
                index="/gitee_test_mindspore_all_20200511";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"*\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"10000d\",\"field\":\"created_at\",\"min_doc_count\":0,\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"user_login.keyword\"}}}}}}";
                break;
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode  dataNode= objectMapper.readTree(responseBody);
        int count=0;
        if(dataNode.get("aggregations").get("datamap")==null){
            count=dataNode.get("aggregations").get("data").get("value").asInt();

        }else{
            for (JsonNode jsonNode : dataNode.get("aggregations").get("datamap").get("buckets")) {
                count+=jsonNode.get("data").get("value").asInt();
            }
        }
        return count+"";
    }

    public String queryNoticusers( String community) throws JsonProcessingException, ExecutionException, InterruptedException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = clientUtils.getClient();
        RequestBuilder builder = clientUtils.getBuilder();
        String index="";
        String queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"source_type_title.keyword:\\\"直接访问\\\" OR source_type_title.keyword:\\\"外部链接\\\" OR source_type_title.keyword:\\\"搜索引擎\\\"\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"1d\",\"field\":\"created_at\",\"min_doc_count\":0,\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"sum\":{\"field\":\"ip_count\"}}}}}}";
        switch (community){
            case "openEuler":
                index="/baidutongji_openeuler_20200702";
                break;
            case "openGauss":
                index="/baidutongji_opengauss_20200702";
                break;
            //todo openlookeng 数据统计由于找不到overview all people 视图 统计未确定
            case "openLookeng":
                index="/baidutongji_openlookeng_20200806";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"!sig_name:\\\"sig-dpdk\\\"\"}}]}},\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"sig_name.keyword\"}}}}";
                break;
            case "mindSpore":
                index="/baidutongji_mindspore_20200603";
                queryjson="{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"source_type_title.keyword:\\\"直接访问\\\" OR source_type_title.keyword:\\\"外部链接\\\" OR source_type_title.keyword:\\\"其他搜索引擎\\\"\"}}]}},\"aggs\":{\"datamap\":{\"date_histogram\":{\"interval\":\"1d\",\"field\":\"created_at\",\"min_doc_count\":0,\"format\":\"epoch_millis\"},\"aggs\":{\"data\":{\"sum\":{\"field\":\"pv_count\"}}}}}}";
                break;
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode  dataNode= objectMapper.readTree(responseBody);
        int count=0;
        if(dataNode.get("aggregations").get("datamap")==null){
            count=dataNode.get("aggregations").get("data").get("value").asInt();

        }else{
            for (JsonNode jsonNode : dataNode.get("aggregations").get("datamap").get("buckets")) {
                count+=jsonNode.get("data").get("value").asInt();
            }
        }
        return count+"";
    }


    public String queryModulenums(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = clientUtils.getClient();
        RequestBuilder builder = clientUtils.getBuilder();
        String index="";
        String queryjson="{\"size\":0,\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"gitee_repo.keyword\"}}}}";
        switch (community){
            case "openEuler":
                index="/gitee_openeuler_all_20200519_2";
                break;
            case "openGauss":
                index="/gitee_opengauss_all_20200513";
                break;
            //todo openlookeng 数据统计由于找不到overview all people 视图 统计未确定
            case "openLookeng":
                index="/gitee_openlookeng_all_20200806";
                break;
            case "mindSpore":
                index="/gitee_test_mindspore_all_20200511";
                break;
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode  dataNode= objectMapper.readTree(responseBody);
        int count=0;
        if(dataNode.get("aggregations").get("datamap")==null){
            count=dataNode.get("aggregations").get("data").get("value").asInt();

        }else{
            for (JsonNode jsonNode : dataNode.get("aggregations").get("datamap").get("buckets")) {
                count+=jsonNode.get("data").get("value").asInt();
            }
        }
        return count+"";
    }

    public String queryAll( String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        String contributors = this.queryContributors(community);
        String users = this.queryUsers(community);
        String noticusers = this.queryNoticusers(community);
        String sigs = this.querySigs(community);
        String modulenums = this.queryModulenums(community);
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("contributors",contributors);
        hashMap.put("users",users);
        hashMap.put("noticusers",noticusers);
        hashMap.put("sigs",sigs);
        hashMap.put("modulenums",modulenums);
        return hashMap.toString();
    }

}
