package com.huawei.Dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.Modules.openEuler;
import com.huawei.Modules.openGauss;
import com.huawei.Modules.openLookeng;
import com.huawei.Utils.AsyncHttpUtil;
import org.asynchttpclient.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author zhxia
 * @date 2020/10/22 12:00
 */
@Repository
public class QueryDao {
    static final String url="eshost:port";
    @Autowired
    static ObjectMapper objectMapper=new ObjectMapper();
    @Autowired
    openEuler openEuler;
    @Autowired
    openGauss openGauss;
    @Autowired
    openLookeng openLookeng;
    //openeuler openlookeng opengauss 测试通过
    public String queryContributors(String community) throws NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        String index="";
        String queryjson="";
        switch (community){
            case "openEuler":
                index=openEuler.getContributors_index();
                queryjson= openEuler.getContributors_queryStr();
                break;
            case "openGauss":
                index=openGauss.getContributors_index();
                queryjson=openGauss.getContributors_queryStr();
                break;
            case "openLookeng":
                index=openLookeng.getContributors_index();
                queryjson=openLookeng.getContributors_queryStr();
                break;
            case "mindSpore":
                return "{\"code\":"+404+",\"data\":{\"contributors\":"+0+"},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build() );
        String contributors = getResult(f, "contributors");
        return contributors;
    }

//测试通过
    public String querySigs(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        String index="";
        String queryjson="";
        switch (community){
            case "openEuler":
                index=openEuler.getSigs_index();
                queryjson=openEuler.getSigs_queryStr();
                break;
            case "openGauss":
            case "mindSpore":
            case "openLookeng":
                return "{\"code\":"+404+",\"data\":{\"sigs\":"+0+"},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        Response response = f.get();
       int statusCode = response.getStatusCode();
       String statusText= response.getStatusText();
        String responseBody = response.getResponseBody(UTF_8);
        JsonNode  dataNode= objectMapper.readTree(responseBody);
        String result = dataNode.get("aggregations").get("data").get("value").toString();
        return "{\"code\":"+statusCode+",\"data\":{\"sigs\":"+Integer.parseInt(result)+"},\"msg\":\""+statusText+"\"}";
    }
//测试通过
    public String queryUsers( String community) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        String index="";
        String queryjson="";
        switch (community){
            case "openEuler":
                index=openEuler.getUsers_index();
                queryjson=openEuler.getUsers_queryStr();
                break;
            case "openGauss":
                index=openGauss.getUsers_index();
               queryjson=openGauss.getUsers_queryStr();
                break;
            case "openLookeng":
                index=openLookeng.getUsers_index();
                queryjson=openLookeng.getUsers_queryStr();
                break;
            case "mindSpore":
                return "{\"code\":"+404+",\"data\":{\"users\":"+0+"},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(QueryDao.url+index+"/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build() );
        String users = getResult(f, "users");
        return users;
    }

    public String queryNoticeusers( String community) throws JsonProcessingException, ExecutionException, InterruptedException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        String index="";
        switch (community){
            case "openEuler":
            case "mindSpore":
            case "openLookeng":
            case "openGauss":
                return "{\"code\":"+404+",\"data\":{\"noticeusers\":"+0+"},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
//        builder.setUrl(QueryDao.url+index+"/_search");
//        builder.setBody(queryjson);
//        //获取执行结果
//        ListenableFuture<Response> f = client.executeRequest(builder.build() );
//        String noticsusers = getResult(f, "noticusers");
//        return noticsusers;
    }


    public String queryModulenums(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        String index="";
        String queryjson="{\"size\":0,\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"gitee_repo.keyword\"}}}}";
        switch (community){
            case "openEuler":
                return getGiteeResNum(openEuler.getAccess_token());
            case "openGauss":
            case "openLookeng":
            case "mindSpore":
                return "{\"code\":"+404+",\"data\":{\"modulenums\":"+0+"},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
//        builder.setUrl(QueryDao.url+index+"/_search");
//        builder.setBody(queryjson);
//        //获取执行结果
//        ListenableFuture<Response> f = client.executeRequest(builder.build() );
//        String modulenums = getResult(f, "modulenums");
//        return modulenums;
    }
    public String getGiteeResNum(String access_token) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        Param access_tokenParam = new Param("access_token", access_token);
        Param visibility= new Param("visibility", "public");
        Param affiliation = new Param("affiliation", "admin");
        Param sort = new Param("sort", "full_name");
        Param direction = new Param("direction", "asc");
        Param q = new Param("q", "src-openEuler");
        Param page = new Param("page", "1");
        Param per_page = new Param("per_page", "1");
        ArrayList<Param> params = new ArrayList<>();
        params.add(access_tokenParam);
        params.add(visibility);
        params.add(affiliation);
        params.add(sort);
        params.add(direction);
        params.add(q);
        params.add(page);
        params.add(per_page);
        Request request = builder.setUrl("https://gitee.com/api/v5/user/repos").setQueryParams(params).addHeader("Content-Type", "application/json;charset=UTF-8").setMethod("GET").build();
        ListenableFuture<Response> responseListenableFuture = client.executeRequest(request);
        Response response = responseListenableFuture.get();
        String total_count = response.getHeader("total_count");
        return "{\"code\":"+response.getStatusCode()+",\"data\":{\"modulenums\":"+(total_count==null?0:total_count)+"},\"msg\":\""+response.getStatusText()+"\"}";
    }
    public String queryBusinessOsv(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = AsyncHttpUtil.getBuilder();
        String index="";
        String queryjson="";
        switch (community){
            case "openEuler":
            case "mindSpore":
                return "{\"code\":"+404+",\"data\":{\"businessOsv\":"+0+"},\"msg\":\"not Found!\"}";
            case "openGauss":
                index="{\"code\":"+200+",\"data\":{\"businessOsv\":"+openGauss.getBusinessOsv_index()+"},\"msg\":\"OK\"}";
                break;
            case "openLookeng":
                index="{\"code\":"+200+",\"data\":{\"businessOsv\":"+openLookeng.getBusinessOsv_index()+"},\"msg\":\"OK\"}";
                break;
            default:
                return "";
        }

        //获取执行结果
        return index;
    }

    public String queryAll( String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        JsonNode contributorsNode = objectMapper.readTree(this.queryContributors(community)).get("data").get("contributors");
        Object contributors=contributorsNode==null?null: contributorsNode.intValue();
        JsonNode usersNode = objectMapper.readTree(this.queryUsers(community)).get("data").get("users");
        Object users=usersNode==null?null: usersNode.intValue();
        JsonNode noticeusersNode = objectMapper.readTree(this.queryNoticeusers(community)).get("data").get("noticeusers");
        Object noticeusers = noticeusersNode == null ? null : noticeusersNode.intValue();
        JsonNode sigsNode = objectMapper.readTree(this.querySigs(community)).get("data").get("sigs");
        Object sigs=sigsNode==null?null:sigsNode.intValue();
        JsonNode modulenumsNode = objectMapper.readTree(this.queryModulenums(community)).get("data").get("modulenums");
        Object modulenums=modulenumsNode==null?null:modulenumsNode.intValue();
        JsonNode businessOsvNode = objectMapper.readTree(this.queryBusinessOsv(community)).get("data").get("businessOsv");
        Object businessOsv=businessOsvNode==null?null:businessOsvNode.intValue();

        String result="{\"code\":"+200+",\"data\":{\"contributors\":"+contributors+",\"users\":"+users+",\"noticeusers\":"+noticeusers+",\"sigs\":"+sigs+",\"modulenums\":"+modulenums+",\"businessosv\":"+businessOsv+"},\"msg\":\""+"OK"+"\"}";
        return result;
    }
    public String getResult(ListenableFuture<Response> f,String dataflage) {
        Response response = null;
        String statusText="请求内部错误";
        double count=0d;
        int statusCode=500;
        try {
            response = f.get();
            statusCode = response.getStatusCode();
            statusText= response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode  dataNode= objectMapper.readTree(responseBody);
            if(dataNode.get("aggregations").get("datamap")==null){
                count=dataNode.get("aggregations").get("data").get("value").asDouble();

            }else{
                for (JsonNode jsonNode : dataNode.get("aggregations").get("datamap").get("buckets")) {
                    count+=jsonNode.get("data").get("value").asDouble();
                }
            }
            String result="{\"code\":"+statusCode+",\"data\":{\""+dataflage+"\":"+Math.round(count)+"},\"msg\":\""+statusText+"\"}";
            return result;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }  catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return "{\"code\":"+statusCode+",\"data\":{\""+dataflage+"\":"+count+"},\"msg\":\""+statusText+"\"}";
    }

}
