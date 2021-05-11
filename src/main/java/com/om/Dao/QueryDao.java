package com.om.Dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.*;
import com.om.Utils.AsyncHttpUtil;
import org.apache.commons.lang3.StringUtils;
import org.asynchttpclient.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author zhxia
 * @date 2020/10/22 12:00
 */
@Repository
public class QueryDao {
    @Autowired
    AsyncHttpUtil asyncHttpUtil;

    @Value("${esurl}")
    String url;

    static ObjectMapper objectMapper = new ObjectMapper();
    @Autowired
    openEuler openEuler;
    @Autowired
    openGauss openGauss;
    @Autowired
    openLookeng openLookeng;
    @Autowired
    mindSpore mindSpore;

    //openeuler openlookeng opengauss 测试通过
    public String queryContributors(String community) throws NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community) {
            case "openEuler":
                index = openEuler.getContributors_index();
                queryjson = openEuler.getContributors_queryStr();
                break;
            case "openGauss":
                index = openGauss.getContributors_index();
                queryjson = openGauss.getContributors_queryStr();
                break;
            case "openLookeng":
                index = openLookeng.getContributors_index();
                queryjson = openLookeng.getContributors_queryStr();
                break;
            case "mindSpore":
                return "{\"code\":" + 404 + ",\"data\":{\"contributors\":" + 0 + "},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String contributors = getResult(f, "contributors");
        return contributors;
    }

    //测试通过
    public String querySigs(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community) {
            case "openEuler":
                index = openEuler.getSigs_index();
                queryjson = openEuler.getSigs_queryStr();
                break;
            case "openGauss":
            case "mindSpore":
            case "openLookeng":
                return "{\"code\":" + 404 + ",\"data\":{\"sigs\":" + 0 + "},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());

        Response response = f.get();
        int statusCode = response.getStatusCode();
        String statusText = response.getStatusText();
        String responseBody = response.getResponseBody(UTF_8);
        JsonNode dataNode = objectMapper.readTree(responseBody);
        String result = dataNode.get("aggregations").get("data").get("value").toString();
        return "{\"code\":" + statusCode + ",\"data\":{\"sigs\":" + Integer.parseInt(result) + "},\"msg\":\"" + statusText + "\"}";
    }

    //测试通过
    public String queryUsers(String community) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community) {
            case "openEuler":
                index = openEuler.getUsers_index();
                queryjson = openEuler.getUsers_queryStr();
                break;
            case "openGauss":
                index = openGauss.getUsers_index();
                queryjson = openGauss.getUsers_queryStr();
                break;
            case "openLookeng":
                index = openLookeng.getUsers_index();
                queryjson = openLookeng.getUsers_queryStr();
                break;
            case "mindSpore":
                return "{\"code\":" + 404 + ",\"data\":{\"users\":" + 0 + "},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String users = getResult(f, "users");
        return users;
    }

    public String queryNoticeusers(String community) throws JsonProcessingException, ExecutionException, InterruptedException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        switch (community) {
            case "openEuler":
            case "mindSpore":
            case "openLookeng":
            case "openGauss":
                return "{\"code\":" + 404 + ",\"data\":{\"noticeusers\":" + 0 + "},\"msg\":\"not Found!\"}";
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
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "{\"size\":0,\"aggs\":{\"data\":{\"cardinality\":{\"field\":\"gitee_repo.keyword\"}}}}";
        switch (community) {
            case "openEuler":
                String result = "";
                String[] communitys = openEuler.getMulticommunity().split(",");
                int temp = 0;
                for (int i = 0; i < communitys.length; i++) {
                    if (i == communitys.length - 1) {
                        temp = temp + objectMapper.readTree(getGiteeResNum(openEuler.getAccess_token(), communitys[i])).get("data").get("modulenums").intValue();
                        result = "{\"code\":200,\"data\":{\"modulenums\":" + temp + "},\"msg\":\"OK\"}";
                    } else {
                        temp = temp + objectMapper.readTree(getGiteeResNum(openEuler.getAccess_token(), communitys[i])).get("data").get("modulenums").intValue();
                    }
                }
                return result;
            case "openGauss":
            case "openLookeng":
            case "mindSpore":
                return "{\"code\":" + 404 + ",\"data\":{\"modulenums\":" + 0 + "},\"msg\":\"not Found!\"}";
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

    public String getGiteeResNum(String access_token, String community) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        Param access_tokenParam = new Param("access_token", access_token);
        Param visibility = new Param("visibility", "public");
        Param affiliation = new Param("affiliation", "admin");
        Param sort = new Param("sort", "full_name");
        Param direction = new Param("direction", "asc");
        Param q = new Param("q", community);
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
        return "{\"code\":" + response.getStatusCode() + ",\"data\":{\"modulenums\":" + (total_count == null ? 0 : total_count) + "},\"msg\":\"" + response.getStatusText() + "\"}";
    }

    public String queryBusinessOsv(String community) throws ExecutionException, InterruptedException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community) {
            case "openEuler":
                index = "{\"code\":" + 200 + ",\"data\":{\"businessOsv\":" + openEuler.getBusinessOsv_index() + "},\"msg\":\"OK\"}";
                break;
            case "mindSpore":
                index = "{\"code\":" + 404 + ",\"data\":{\"businessOsv\":" + 0 + "},\"msg\":\"not Found!\"}";
                break;
            case "openGauss":
                index = "{\"code\":" + 200 + ",\"data\":{\"businessOsv\":" + openGauss.getBusinessOsv_index() + "},\"msg\":\"OK\"}";
                break;
            case "openLookeng":
                index = "{\"code\":" + 200 + ",\"data\":{\"businessOsv\":" + openLookeng.getBusinessOsv_index() + "},\"msg\":\"OK\"}";
                break;
            default:
                return "";
        }

        //获取执行结果
        return index;
    }

    public String querycommunitymembers(String community) throws NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community) {
            case "openEuler":
                index = openEuler.getCommunitymembers_index();
                queryjson = openEuler.getCommunitymembers_queryStr();
                break;
            case "openGauss":
                index = openGauss.getCommunitymembers_index();
                queryjson = openGauss.getCommunitymembers_queryStr();
                break;
            case "openLookeng":
                index = openLookeng.getCommunitymembers_index();
                queryjson = openLookeng.getCommunitymembers_queryStr();
                break;
            case "mindSpore":
                return "{\"code\":" + 404 + ",\"data\":{\"users\":" + 0 + "},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String communitymembers = getResult(f, "communitymembers");
        return communitymembers;
    }

    public String queryAll(String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        JsonNode contributorsNode = objectMapper.readTree(this.queryContributors(community)).get("data").get("contributors");
        Object contributors = contributorsNode == null ? null : contributorsNode.intValue();
        JsonNode usersNode = objectMapper.readTree(this.queryUsers(community)).get("data").get("users");
        Object users = usersNode == null ? null : usersNode.intValue();
        JsonNode noticeusersNode = objectMapper.readTree(this.queryNoticeusers(community)).get("data").get("noticeusers");
        Object noticeusers = noticeusersNode == null ? null : noticeusersNode.intValue();
        JsonNode sigsNode = objectMapper.readTree(this.querySigs(community)).get("data").get("sigs");
        Object sigs = sigsNode == null ? null : sigsNode.intValue();
        JsonNode modulenumsNode = objectMapper.readTree(this.queryModulenums(community)).get("data").get("modulenums");
        Object modulenums = modulenumsNode == null ? null : modulenumsNode.intValue();
        JsonNode businessOsvNode = objectMapper.readTree(this.queryBusinessOsv(community)).get("data").get("businessOsv");
        Object businessOsv = businessOsvNode == null ? null : businessOsvNode.intValue();
        JsonNode communityMembersNode = objectMapper.readTree(this.querycommunitymembers(community)).get("data").get("communitymembers");
        Object communityMembers = businessOsvNode == null ? null : communityMembersNode.intValue();
        String result = "{\"code\":" + 200 + ",\"data\":{\"contributors\":" + contributors + ",\"users\":" + users + ",\"noticeusers\":" + noticeusers + ",\"sigs\":" + sigs + ",\"modulenums\":" + modulenums + ",\"businessosv\":" + businessOsv + ",\"communitymembers\":" + communityMembers + "},\"msg\":\"" + "OK" + "\"}";
        return result;
    }

    public String getResult(ListenableFuture<Response> f, String dataflage) {
        Response response = null;
        String statusText = "请求内部错误";
        double count = 0d;
        int statusCode = 500;
        try {
            response = f.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            if (dataNode.get("aggregations").get("datamap") == null) {
                count = dataNode.get("aggregations").get("data").get("value").asDouble();

            } else {
                for (JsonNode jsonNode : dataNode.get("aggregations").get("datamap").get("buckets")) {
                    count += jsonNode.get("data").get("value").asDouble();
                }
            }
            String result = "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + Math.round(count) + "},\"msg\":\"" + statusText + "\"}";
            return result;
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + count + "},\"msg\":\"" + statusText + "\"}";
    }

    public String query(String index, String querystr) throws NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(String.format(querystr));
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        Response response = null;
        try {
            response = f.get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        if (response.getStatusCode() == 404) {
            return "";
        } else if (response.getStatusCode() != 200) {
            return null;
        } else {
            String responseBody = response.getResponseBody(UTF_8);
            return responseBody;
        }


    }

    public String queryCount(String community, String item) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";

        switch (community) {
            case "openEuler":
                index = openEuler.getGiteeAllIndex();
                queryjson = openEuler.getCountQueryStr(item);
                break;
            case "openGauss":
                index = openGauss.getGiteeAllIndex();
                queryjson = openGauss.getCountQueryStr(item);
                break;
            case "openLookeng":
                index = openLookeng.getGiteeAllIndex();
                queryjson = openLookeng.getCountQueryStr(item);
                break;
            case "mindSpore":
                index = mindSpore.getGiteeAllIndex();
                queryjson = mindSpore.getCountQueryStr(item);
                break;
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_count");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        return getCount(f, item);
    }

    public String getCount(ListenableFuture<Response> f, String dataflage) {
        Response response;
        String statusText = "请求内部错误";
        long count = 0;
        int statusCode = 500;

        try {
            response = f.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            count = dataNode.get("count").asLong();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + count + "},\"msg\":\"" + statusText + "\"}";
    }

    public String queryDownload(String community, String item) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        String valueField = "";
        String queryDockerHubjson = "";

        switch (community) {
            case "openEuler":
                index = openEuler.getDownloadQueryIndex();
                queryjson = openEuler.getDownloadQueryStr();
                break;
            case "openGauss":
                index = openGauss.getDownloadQueryIndex();
                queryjson = openGauss.getDownloadQueryStr();
                break;
            case "openLookeng":
                index = openLookeng.getDownloadQueryIndex();
                queryjson = openLookeng.getDownloadQueryStr();
                break;
            case "mindSpore":
                index = mindSpore.getDownloadQueryIndex();
                queryjson = mindSpore.getDownloadQueryStr();
                valueField = "all_download";
                queryDockerHubjson = mindSpore.getDownloadDockerHubQueryStr();
                break;
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());

        //mindspore多个下载需要加起来
        ListenableFuture<Response> fDockerHub = null;
        if (StringUtils.isNotBlank(queryDockerHubjson)) {
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryDockerHubjson);
            //获取执行结果
            fDockerHub = client.executeRequest(builder.build());
        }

        return getDownload(f, valueField, fDockerHub, item);
    }

    public String getDownload(ListenableFuture<Response> f, String valueField, ListenableFuture<Response> fDockerHub, String dataflage) {
        Response response;
        String statusText = "请求内部错误";
        long count = 0;
        int statusCode = 500;

        try {
            response = f.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_by_field").get("buckets").elements();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                if (StringUtils.isBlank(valueField)) {
                    count = bucket.get("doc_count").asLong();
                    break;
                }
                Iterator<JsonNode> hits = bucket.get("last").get("hits").get("hits").elements();
                while (hits.hasNext()) {
                    JsonNode hit = hits.next();
                    count = hit.get("_source").get(valueField).asLong();
                    break;
                }
                break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (fDockerHub != null) {
            try {
                response = fDockerHub.get();
                statusCode = response.getStatusCode();
                statusText = response.getStatusText();
                String responseBody = response.getResponseBody(UTF_8);
                JsonNode dataNode = objectMapper.readTree(responseBody);
                Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_by_field").get("buckets").elements();
                while (buckets.hasNext()) {
                    JsonNode bucket = buckets.next();
                    count += bucket.get("sum").get("value").asLong();
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + count + "},\"msg\":\"" + statusText + "\"}";
    }
}
