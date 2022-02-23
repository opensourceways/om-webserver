package com.om.Dao;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.*;
import com.om.Utils.AsyncHttpUtil;
import com.om.Utils.CsvFileUtil;
import com.om.Utils.EsQueryUtils;
import com.om.Utils.HttpClientUtils;
import com.om.Vo.BlueZoneContributeVo;
import com.om.Vo.BlueZoneUserVo;
import org.apache.commons.lang3.StringUtils;
import org.asynchttpclient.*;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

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
    @Autowired
    BlueZone blueZone;
    @Autowired
    StarFork starFork;

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

    public String queryDurationAggFromProjectHostarchPackage(String community) throws NoSuchAlgorithmException, KeyManagementException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getDurationAggIndex();
                queryjson = openEuler.getDurationAggQueryStr();
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
                return "{\"code\":" + 404 + ",\"data\":{\"DurationSecs\":" + 0 + "},\"msg\":\"not Found!\"}";
            default:
                return "";
        }

        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String avgDuration = parseDurationAggFromProjectHostarchPackageResult(f, "avgDuration");
        return avgDuration;
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
        Iterator<JsonNode> buckets = dataNode.get("aggregations").get("2").get("buckets").elements();
        long count = 0;
        while (buckets.hasNext()) {
            JsonNode bucket = buckets.next();
            count += bucket.get("1").get("value").asLong();
        }

        return "{\"code\":" + statusCode + ",\"data\":{\"sigs\":" + count + "},\"msg\":\"" + statusText + "\"}";
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

                String[] indexs = index.split(";");
                String[] queryjsons = queryjson.split(";");
                double user_count = 0d;
                int statusCode = 500;
                String statusText = "请求内部错误";
                for (int i = 0; i < indexs.length; i++) {
                    index = indexs[i];
                    queryjson = queryjsons[i];

                    builder.setUrl(this.url + index + "/_search");
                    builder.setBody(queryjson);
                    //获取执行结果
                    ListenableFuture<Response> f = client.executeRequest(builder.build());
                    String users = getResult(f, "users");
                    JsonNode dataNode = objectMapper.readTree(users);
                    statusCode = dataNode.get("code").intValue();
                    user_count += dataNode.get("data").get("users").intValue();
                    statusText = dataNode.get("msg").textValue();
                }
                return "{\"code\":" + statusCode + ",\"data\":{\"users\":" + Math.round(user_count) + "},\"msg\":\"" + statusText + "\"}";
            case "openGauss":
                index = openGauss.getUsers_index();
                queryjson = openGauss.getUsers_queryStr();
                break;
            case "openLookeng":
                index = openLookeng.getUsers_index();
                queryjson = openLookeng.getUsers_queryStr();
                builder.setUrl(this.url + index + "/_count");
                builder.setBody(queryjson);
                ListenableFuture<Response> f = client.executeRequest(builder.build());
                return getCountResult(f, "users");
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
        JsonNode downloadNode = objectMapper.readTree(this.queryDownload(community, "download")).get("data").get("download");
        Object downloads = downloadNode == null ? null : downloadNode.intValue();
        String result = "{\"code\":" + 200 + ",\"data\":{\"downloads\":" + downloads + ",\"contributors\":" + contributors + ",\"users\":" + users + ",\"noticeusers\":" + noticeusers + ",\"sigs\":" + sigs + ",\"modulenums\":" + modulenums + ",\"businessosv\":" + businessOsv + ",\"communitymembers\":" + communityMembers + "},\"msg\":\"" + "OK" + "\"}";
        return result;
    }

    public String getCountResult(ListenableFuture<Response> f, String dataflage) {
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
            count = dataNode.get("count").asLong();
            String result = "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + Math.round(count) + "},\"msg\":\"" + statusText + "\"}";
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + count + "},\"msg\":\"" + statusText + "\"}";
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

    public String parseDurationAggFromProjectHostarchPackageResult(ListenableFuture<Response> f, String dataflage) {
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

            JsonNode dataMap = dataNode.get("aggregations").get("datamap");
            if (dataMap == null) {
                return null;
            }
            JSONObject projectObj = new JSONObject();
            for (JsonNode project_bucket : dataMap.get("buckets")) {
                String projectName = project_bucket.get("key").asText();
                JsonNode hostarchNode = project_bucket.get("group_by_hostarch");

                JSONObject archObj = new JSONObject();
                for (JsonNode arch_bucket : hostarchNode.get("buckets")) {
                    String archName = arch_bucket.get("key").asText();
                    JsonNode archNode = arch_bucket.get("group_by_package");

                    JSONObject packageObj = new JSONObject();
                    for (JsonNode package_bucket : archNode.get("buckets")) {
                        String packageName = package_bucket.get("key").asText();
                        JsonNode value = package_bucket.get("avg_of_duration").get("value");
                        Double avgDurationSecs = Double.valueOf((new DecimalFormat("0.000")).format(value.asDouble()));
                        packageObj.put(packageName, avgDurationSecs);
                    }
                    archObj.put(archName, packageObj);
                }
                projectObj.put(projectName, archObj);
            }
            String str_data = projectObj.toString();
            String result = "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + str_data + "},\"msg\":\"" + statusText + "\"}";
            return result;
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        } catch (JSONException e) {
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
            case "openLookeng":
                return "{\"code\":" + 404 + ",\"data\":{\"" + item + "\":" + 0 + "},\"msg\":\"Not Found!\"}";
            case "openGauss":
                index = openGauss.getDownloadQueryIndex();
                queryjson = openGauss.getDownloadQueryStr();
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

    public String queryBlueZoneContributes(BlueZoneContributeVo body, String item) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();

        String index = blueZone.getBlueZoneContributesIndex();
        String queryjson = getBlueZoneContributesQuery(body);

        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        ListenableFuture<Response> f = client.executeRequest(builder.build());

        return getBlueZoneContributesRes(f, item);
    }

    private String getBlueZoneContributesQuery(BlueZoneContributeVo body) {
        List<String> giteeIds = body.getGitee_id();
        List<String> githubIds = body.getGithub_id();
        String startTime = body.getStartTime();
        String endTime = body.getEndTime();
        String query;

        //请求参数是否有gitee_id和github_id
        StringBuilder queryString = new StringBuilder();
        if (giteeIds != null && !giteeIds.isEmpty()) {
            for (String giteeId : giteeIds) {
                queryString.append("gitee_id.keyword:\\\"").append(giteeId).append("\\\" OR ");
            }
        }
        if (githubIds != null && !githubIds.isEmpty()) {
            for (String githubId : githubIds) {
                queryString.append("github_id.keyword:\\\"").append(githubId).append("\\\" OR ");
            }
        }
        String qStr = queryString.toString();
        if (StringUtils.isBlank(qStr)) qStr = "*";
        else qStr = qStr.substring(0, qStr.length() - 4);

        //请求参数是否有时间范围
        if (StringUtils.isNotBlank(startTime) && StringUtils.isNotBlank(endTime)) {
            String queryStr = "{\"size\": 10000,\"query\": {\"bool\": {\"filter\": [" +
                    "{\"range\": {\"created_at\": {\"gte\": \"%s\",\"lte\": \"%s\"}}}," +
                    "{\"query_string\": {\"analyze_wildcard\": true,\"query\": \"%s\"}}]}}}";
            query = String.format(queryStr, startTime, endTime, qStr);
        } else {
            String queryStr = "{\"size\": 10000,\"query\": {\"bool\": {\"filter\": [" +
                    "{\"query_string\": {\"analyze_wildcard\": true,\"query\": \"%s\"}}]}}}";
            query = String.format(queryStr, qStr);
        }

        return query;
    }

    public String getBlueZoneContributesRes(ListenableFuture<Response> f, String dataflage) {
        Response response = null;
        String statusText = "请求内部错误";
        String badReq = "参数有误";
        int statusCode = 500;
        try {
            response = f.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            JsonNode hits = dataNode.get("hits").get("hits");
            Iterator<JsonNode> it = hits.elements();
            ArrayList<Object> prList = new ArrayList<>();
            ArrayList<Object> issueList = new ArrayList<>();
            ArrayList<Object> commentList = new ArrayList<>();
            ArrayList<Object> commitList = new ArrayList<>();
            while (it.hasNext()) {
                JsonNode hit = it.next();
                String id = hit.get("_id").asText();
                JsonNode source = hit.get("_source");
                if (source.has("is_pr")) {
                    Map sourceMap = objectMapper.convertValue(source, Map.class);
                    sourceMap.put("id", id);
                    sourceMap.remove("url");
                    JsonNode pr = objectMapper.valueToTree(sourceMap);
                    prList.add(pr);
                }
                if (source.has("is_issue")) {
                    Map sourceMap = objectMapper.convertValue(source, Map.class);
                    sourceMap.put("id", id);
                    sourceMap.remove("url");
                    JsonNode pr = objectMapper.valueToTree(sourceMap);
                    issueList.add(sourceMap);
                }
                if (source.has("is_comment")) {
                    Map sourceMap = objectMapper.convertValue(source, Map.class);
                    sourceMap.put("id", id);
                    sourceMap.remove("url");
                    JsonNode pr = objectMapper.valueToTree(sourceMap);
                    commentList.add(sourceMap);
                }
                if (source.has("is_commit")) {
                    Map sourceMap = objectMapper.convertValue(source, Map.class);
                    sourceMap.put("id", id);
                    sourceMap.remove("url");
                    JsonNode pr = objectMapper.valueToTree(sourceMap);
                    commitList.add(sourceMap);
                }
            }
            HashMap dataMap = new HashMap();
            dataMap.put("prs", prList);
            dataMap.put("issues", issueList);
            dataMap.put("comments", commentList);
            dataMap.put("commits", commitList);
            JsonNode jsonNode1 = objectMapper.valueToTree(dataMap);

            HashMap resMap = new HashMap();
            resMap.put("code", statusCode);
            resMap.put("data", jsonNode1);
            resMap.put("msg", statusText);
            String s = objectMapper.valueToTree(resMap).toString();

            return s;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + badReq + "},\"msg\":\"" + statusText + "\"}";
    }

    public String putBlueZoneUser(BlueZoneUserVo userVo, String item, Environment env) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        BulkRequest request = new BulkRequest();

        LocalDateTime now = LocalDateTime.now();
        String nowStr = now.toString().split("\\.")[0] + "+08:00";

        String index = blueZone.getBlueZoneUsersIndex();
        List<BlueZoneUser> users = userVo.getUsers();
        for (BlueZoneUser user : users) {
            String id;
            if (StringUtils.isNotBlank(user.getGitee_id())) id = user.getGitee_id();
            else if (StringUtils.isNotBlank(user.getGithub_id())) id = user.getGithub_id();
            else continue;

            Map resMap = objectMapper.convertValue(user, Map.class);
            resMap.put("created_at", nowStr);
            resMap.put("emails", user.getEmail());
            resMap.remove("email");
            request.add(new IndexRequest(index, "_doc", id).source(resMap));
        }

        if (request.requests().size() != 0)
            restHighLevelClient.bulk(request, RequestOptions.DEFAULT);
        restHighLevelClient.close();

        String res = "{\"code\":200,\"data\":{\"users_count\":\"0\"},\"msg\":\"there`s no user\"}";
        if (users.size() > 0) {
            res = String.format("{\"code\":200,\"data\":{\"%s_count\":\"%s\"},\"msg\":\"update success\"}", item, users.size());
        }
        return res;
    }

    public String queryOrgStarAndFork(String community, String item) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();

        String index = starFork.getStar_fork_index();
        String queryjson = starFork.getStar_fork_queryStr();

        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        return getOrgStarAndForkRes(f, item, community);
    }

    public String getOrgStarAndForkRes(ListenableFuture<Response> f, String dataflage, String community) {
        Response response;
        String statusText;
        String badReq;
        int statusCode;
        List<String> communities = Arrays.stream(community.split(",")).map(String::toLowerCase).collect(Collectors.toList());
        try {
            response = f.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            JsonNode buckets = dataNode.get("aggregations").get("owner").get("buckets");
            Iterator<JsonNode> it = buckets.elements();

            ArrayList<Object> res = new ArrayList<>();
            while (it.hasNext()) {
                JsonNode bucket = it.next();
                String com = bucket.get("key").asText();
                if (!communities.get(0).equals("allproject") && !communities.contains(com)) {
                    continue;
                }
                HashMap dataMap = new HashMap();
                dataMap.put("community", com);
                dataMap.put("stars", bucket.get("stars").get("value").asInt());
                dataMap.put("forks", bucket.get("forks").get("value").asInt());
                res.add(objectMapper.valueToTree(dataMap));
            }

            HashMap resMap = new HashMap();
            resMap.put("code", statusCode);
            resMap.put("data", res);
            resMap.put("msg", statusText);
            String s = objectMapper.valueToTree(resMap).toString();

            return s;
        } catch (Exception e) {
            statusText = "fail";
            badReq = "query error";
            statusCode = 500;
            e.printStackTrace();
        }
        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":\"" + badReq + "\"},\"msg\":\"" + statusText + "\"}";
    }

    public String queryCveDetails(String community, String item, String lastCursor, String pageSize, Environment env) {
        String indexName;
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getCveDetailsQueryIndex();
                break;
            case "opengauss":
                indexName = openGauss.getCveDetailsQueryIndex();
                break;
            case "openlookeng":
                indexName = openLookeng.getCveDetailsQueryIndex();
                break;
            case "mindspore":
                indexName = mindSpore.getCveDetailsQueryIndex();
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        EsQueryUtils esQueryUtils = new EsQueryUtils();
        if (pageSize == null) {
            return esQueryUtils.esScroll(restHighLevelClient, item, indexName);
        }
        return esQueryUtils.esFromId(restHighLevelClient, item, lastCursor, Integer.parseInt(pageSize), indexName);
    }

    public String queryNewYear(String community, String user, String item, Environment env) {
        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        BulkRequest request = new BulkRequest();

        LocalDateTime now = LocalDateTime.now();
        String nowStr = now.toString().split("\\.")[0] + "+08:00";
        HashMap<String, String> indexMap = new HashMap<>();
        indexMap.put("created_at", nowStr);
        indexMap.put("community", community);
        indexMap.put("user_login", user);
        String id = nowStr + "_" + community + "_" + user;
        request.add(new IndexRequest("new_year_" + item, "_doc", id).source(indexMap));
        if (request.requests().size() != 0) {
            try {
                restHighLevelClient.bulk(request, RequestOptions.DEFAULT);
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    restHighLevelClient.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        String csvName = "new-year/" + community.toLowerCase() + "_" + item + ".csv";
        List<HashMap<String, Object>> datas = CsvFileUtil.readFile(csvName);

        HashMap resMap = new HashMap();
        resMap.put("code", 200);
        resMap.put("msg", "OK");
        if (datas == null) {
            resMap.put("data", new ArrayList<>());
        } else if (user == null) {
            resMap.put("data", datas);
        } else {
            List<HashMap<String, Object>> user_login = datas.stream().filter(m -> m.getOrDefault("user_login", "").equals(user)).collect(Collectors.toList());
            resMap.put("data", user_login);
        }

        String s = objectMapper.valueToTree(resMap).toString();

        return s;
    }

    public String queryBugQuestionnaire(String community, String item, String lastCursor, String pageSize, Environment env) {
        String indexName;
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
        String[] userpass = Objects.requireNonNull(env.getProperty("secure.userpass")).split(":");
        String host = env.getProperty("es.secure.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        EsQueryUtils esQueryUtils = new EsQueryUtils();

        if (pageSize == null) {
            return esQueryUtils.esScroll(restHighLevelClient, item, indexName);
        }
        return esQueryUtils.esFromId(restHighLevelClient, item, lastCursor, Integer.parseInt(pageSize), indexName);
    }


}
