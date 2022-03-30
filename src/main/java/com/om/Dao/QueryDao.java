package com.om.Dao;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Modules.*;
import com.om.Modules.yaml.CommunityPartnersYaml;
import com.om.Modules.yaml.CommunityPartnersYamlInfo;
import com.om.Modules.yaml.CompanyYaml;
import com.om.Modules.yaml.CompanyYamlInfo;
import com.om.Utils.*;
import com.om.Vo.BlueZoneContributeVo;
import com.om.Vo.BlueZoneUserVo;
import com.om.Vo.IsoBuildTimesVo;
import com.om.Vo.SigDetailsVo;
import org.apache.commons.lang3.StringUtils;
import org.asynchttpclient.*;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.json.JSONArray;
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

    @Value("${company.name.yaml}")
    String companyNameYaml;

    @Value("${community.partners.yaml}")
    String communityPartnersYaml;

    @Value("${skip.robot.user}")
    String robotUser;

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
    public String queryContributors(String community) throws NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getContributors_index();
                queryjson = openEuler.getContributors_queryStr();
                break;
            case "opengauss":
                index = openGauss.getContributors_index();
                queryjson = openGauss.getContributors_queryStr();
                break;
            case "openlookeng":
                index = openLookeng.getContributors_index();
                queryjson = openLookeng.getContributors_queryStr();
                String[] indexs = index.split(";");
                double contributors_count = 0d;
                int statusCode = 500;
                String statusText = "query error";
                for (int i = 0; i < indexs.length; i++) {
                    index = indexs[i];
                    builder.setUrl(this.url + index + "/_search");
                    builder.setBody(queryjson);
                    //获取执行结果
                    ListenableFuture<Response> f = client.executeRequest(builder.build());
                    String users = getResult(f, "contributors");
                    JsonNode dataNode = objectMapper.readTree(users);
                    statusCode = dataNode.get("code").intValue();
                    contributors_count += dataNode.get("data").get("contributors").intValue();
                    statusText = dataNode.get("msg").textValue();
                }
                return "{\"code\":" + statusCode + ",\"data\":{\"contributors\":" + Math.round(contributors_count) + "},\"msg\":\"" + statusText + "\"}";
            case "mindspore":
                index = mindSpore.getContributors_index();
                queryjson = mindSpore.getContributors_queryStr();
                break;
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
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getSigs_index();
                queryjson = openEuler.getSigs_queryStr();
                break;
            case "opengauss":
                index = openGauss.getSigs_index();
                queryjson = openGauss.getSigs_queryStr();
                break;
            case "mindspore":
                index = mindSpore.getSigs_index();
                queryjson = mindSpore.getSigs_queryStr();
                return "{\"code\":" + 404 + ",\"data\":{\"sigs\":" + queryjson + "},\"msg\":\"not Found!\"}";
            case "openlookeng":
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
        switch (community.toLowerCase()) {
            case "openeuler":
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
            case "opengauss":
                index = openGauss.getUsers_index();
                queryjson = openGauss.getUsers_queryStr();
                break;
            case "openlookeng":
                index = openLookeng.getUsers_index();
                queryjson = openLookeng.getUsers_queryStr();
                builder.setUrl(this.url + index + "/_count");
                builder.setBody(queryjson);
                ListenableFuture<Response> f = client.executeRequest(builder.build());
                return getCountResult(f, "users");
            case "mindspore":
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
        switch (community.toLowerCase()) {
            case "openeuler":
            case "mindspore":
            case "openlookeng":
            case "opengauss":
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
        switch (community.toLowerCase()) {
            case "openeuler":
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
            case "opengauss":
            case "openlookeng":
            case "mindspore":
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
        switch (community.toLowerCase()) {
            case "openeuler":
                index = "{\"code\":" + 200 + ",\"data\":{\"businessOsv\":" + openEuler.getBusinessOsv_index() + "},\"msg\":\"OK\"}";
                break;
            case "mindspore":
                index = "{\"code\":" + 404 + ",\"data\":{\"businessOsv\":" + 0 + "},\"msg\":\"not Found!\"}";
                break;
            case "opengauss":
                index = "{\"code\":" + 200 + ",\"data\":{\"businessOsv\":" + openGauss.getBusinessOsv_index() + "},\"msg\":\"OK\"}";
                break;
            case "openlookeng":
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
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getCommunitymembers_index();
                queryjson = openEuler.getCommunitymembers_queryStr();
                break;
            case "opengauss":
                index = openGauss.getCommunitymembers_index();
                queryjson = openGauss.getCommunitymembers_queryStr();
                break;
            case "openlookeng":
                index = openLookeng.getCommunitymembers_index();
                queryjson = openLookeng.getCommunitymembers_queryStr();
                break;
            case "mindspore":
                return "{\"code\":" + 404 + ",\"data\":{\"communitymembers\":" + 0 + "},\"msg\":\"not Found!\"}";
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
        Map<String, Object> contributes = queryContributes(community, "contributes");
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
        Object downloadUser = 0;
        if (community.toLowerCase().equals("mindspore") || community.toLowerCase().equals("opengauss")) {
            downloadUser = users;
            users = downloads;
        }
        contributes.put("downloads", downloads);
        contributes.put("contributors", contributors);
        contributes.put("users", users);
        contributes.put("noticeusers", noticeusers);
        contributes.put("sigs", sigs);
        contributes.put("modulenums", modulenums);
        contributes.put("businessosv", businessOsv);
        contributes.put("communitymembers", communityMembers);
        contributes.put("downloaduser", downloadUser);

        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", 200);
        resMap.put("data", contributes);
        resMap.put("msg", "success");
        return objectMapper.valueToTree(resMap).toString();

//        String result = "{\"code\":" + 200 + ",\"data\":{\"downloads\":" + downloads + ",\"contributors\":" + contributors + ",\"users\":" + users + ",\"noticeusers\":" + noticeusers + ",\"sigs\":" + sigs + ",\"modulenums\":" + modulenums + ",\"businessosv\":" + businessOsv + ",\"communitymembers\":" + communityMembers + "},\"msg\":\"" + "OK" + "\"}";
//        return result;
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

        switch (community.toLowerCase()) {
            case "openeuler":
            case "openlookeng":
                return "{\"code\":" + 404 + ",\"data\":{\"" + item + "\":" + 0 + "},\"msg\":\"Not Found!\"}";
            case "opengauss":
                index = openGauss.getDownloadQueryIndex();
                queryjson = openGauss.getDownloadQueryStr();
                break;
            case "mindspore":
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
                dataMap.put("commits", bucket.get("commits").get("value").asInt());
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

    public String queryObsDetails(String community, String item, String branch, String limit) {
        String indexName;
        String queryjson;
        String packageQueryjson;
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getObsDetailsIndex();
                queryjson = openEuler.getObsDetailsIndexQueryStr();
                packageQueryjson = openEuler.getObsPackageQueryStr();
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        try {
            ArrayList<JsonNode> dataList = getObsDetails(indexName, packageQueryjson, queryjson, branch, limit);
            HashMap resMap = new HashMap();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            String s = objectMapper.valueToTree(resMap).toString();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
    }

    public ArrayList<JsonNode> getObsDetails(String index, String packageQueryStr, String obsDetailsQueryStr, String branch, String limit) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        int size = (limit == null) ? 5 : Integer.parseInt(limit);
        // 1、获取某个工程下的所有包
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();

        builder.setUrl(this.url + index + "/_search");
        builder.setBody(String.format(packageQueryStr, branch));
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode dataNode = objectMapper.readTree(responseBody);
        JsonNode jsonNode = dataNode.get("aggregations").get("package").get("buckets");
        Iterator<JsonNode> packages = jsonNode.elements();

        ArrayList<JsonNode> dataList = new ArrayList<>();
        while (packages.hasNext()) {
            String packageName = packages.next().get("key").asText();
            builder.setBody(String.format(obsDetailsQueryStr, branch, packageName, size));
            f = client.executeRequest(builder.build());
            responseBody = f.get().getResponseBody(UTF_8);
            dataNode = objectMapper.readTree(responseBody);
            JsonNode hits = dataNode.get("hits").get("hits");
            Iterator<JsonNode> it = hits.elements();

            HashMap<String, Object> packageMap = new HashMap<>();
            ArrayList<Long> buildTimes = new ArrayList<>();
            boolean is_head = true;
            // 2、获取某个工程每个包最近的数据
            while (it.hasNext()) {
                JsonNode hit = it.next();
                JsonNode source = hit.get("_source");
                if (is_head) {
                    packageMap.put("repo_name", source.get("package").asText());
                    packageMap.put("obs_version", source.get("versrel").asText());
                    packageMap.put("architecture", source.get("hostarch").asText());
                    packageMap.put("obs_branch", source.get("project").asText());
                    packageMap.put("build_state", source.get("code").asText());
                }
                buildTimes.add(source.get("duration").asLong());
                is_head = false;

            }
            packageMap.put("history_build_times", buildTimes);
            JsonNode resNode = objectMapper.valueToTree(packageMap);
            dataList.add(resNode);
        }

        return dataList;
    }

    public String queryIsoBuildTimes(IsoBuildTimesVo body, String item) {
        String indexName;
        String queryjson;
        String community = body.getCommunity();
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getIsoBuildIndex();
                queryjson = openEuler.getIsoBuildIndexQueryStr();
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        try {
            ArrayList<JsonNode> dataList = getIsoBuildTimes(indexName, queryjson, body);
            HashMap resMap = new HashMap();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            String s = objectMapper.valueToTree(resMap).toString();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
    }

    public ArrayList<JsonNode> getIsoBuildTimes(String index, String query, IsoBuildTimesVo body) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        List<String> branchs = new ArrayList<>();
        Integer limit = body.getLimit();
        int size = (limit == null) ? 10 : limit;

        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        builder.setUrl(this.url + index + "/_search");

        // 获取所有的工程
        if (body.getBranchs() == null) {
            builder.setBody("{\"size\": 0,\"aggs\": {\"obs_project\": {\"terms\": {\"field\": \"obs_project.keyword\",\"size\": 10000,\"min_doc_count\": 1}}}}");
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            JsonNode jsonNode = dataNode.get("aggregations").get("obs_project").get("buckets");
            Iterator<JsonNode> it = jsonNode.elements();
            while (it.hasNext()) {
                JsonNode next = it.next();
                branchs.add(next.get("key").asText());
            }
        } else {
            branchs = body.getBranchs();
        }

        ArrayList<JsonNode> dataList = new ArrayList<>();
        HashMap<String, Object> dataMap = new HashMap<>();
        for (String branch : branchs) {
            builder.setBody(String.format(query, branch, size));
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            JsonNode jsonNode = dataNode.get("hits").get("hits");
            Iterator<JsonNode> it = jsonNode.elements();
            while (it.hasNext()) {
                JsonNode hit = it.next();
                JsonNode source = hit.get("_source");
                dataMap.put("branch", source.get("obs_project").asText());
                dataMap.put("date", source.get("archive_start").asText());
                dataMap.put("build_result", "");
                dataMap.put("build_time", source.get("build_version_time").asLong());
                dataMap.put("iso_time", source.get("make_ios_time").asLong());
                JsonNode resNode = objectMapper.valueToTree(dataMap);
                dataList.add(resNode);
            }

        }

        return dataList;
    }

    public String querySigDetails(SigDetailsVo body, String item) {
        String indexName;
        String queryjson;
        String community = body.getCommunity();
        switch (community.toLowerCase()) {
            case "openeuler":
                indexName = openEuler.getSigDetailsIndex();
                queryjson = openEuler.getSigDetailsIndexQueryStr();
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        try {
            ArrayList<JsonNode> dataList = getSigDetails(indexName, queryjson, body);
            HashMap resMap = new HashMap();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            String s = objectMapper.valueToTree(resMap).toString();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
    }

    public ArrayList<JsonNode> getSigDetails(String index, String query, SigDetailsVo body) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        List<String> sig_names = body.getSigs();

        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        builder.setUrl(this.url + index + "/_search");

        builder.setBody(query);
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode dataNode = objectMapper.readTree(responseBody);

        ArrayList<JsonNode> dataList = new ArrayList<>();
        JsonNode jsonNode = dataNode.get("hits").get("hits");
        Iterator<JsonNode> it = jsonNode.elements();
        while (it.hasNext()) {
            SigDetails sig = new SigDetails();
            JsonNode hit = it.next();
            JsonNode source = hit.get("_source");

            ArrayList<SigDetailsMaintainer> maintainers = new ArrayList<>();
            JsonNode maintainerInfo = source.get("maintainer_info");
            if (maintainerInfo != null) {
                Iterator<JsonNode> jsonNodes = maintainerInfo.elements();
                while (jsonNodes.hasNext()) {
                    JsonNode maintainer = jsonNodes.next();
                    JsonNode giteeId = maintainer.get("gitee_id");
                    String giteeIdStr = giteeId == null ? "" : giteeId.asText();
                    JsonNode email = maintainer.get("email");
                    String emailStr = email == null ? "" : email.asText();
                    maintainers.add(new SigDetailsMaintainer(giteeIdStr, emailStr));  //TODO
                }
            } else {
                Iterator<JsonNode> jsonNodes = source.get("maintainers").elements();
                while (jsonNodes.hasNext()) {
                    JsonNode maintainer = jsonNodes.next();
                    maintainers.add(new SigDetailsMaintainer(maintainer.textValue(), ""));  //TODO
                }
            }

            ArrayList<String> repos = new ArrayList<>();
            Iterator<JsonNode> repoNodes = source.get("repos").elements();
            while (repoNodes.hasNext()) {
                JsonNode repo = repoNodes.next();
                repos.add(repo.textValue());
            }

            sig.setName(source.get("sig_name").asText());
            sig.setDescription(""/*source.get("description").asText()*/);  //TODO
            sig.setMaintainer(maintainers);
            sig.setRepositories(repos);
            JsonNode resNode = objectMapper.convertValue(sig, JsonNode.class);

            if (sig_names == null) {
                dataList.add(resNode);
            } else if (sig_names.contains(sig.getName())) {
                dataList.add(resNode);
            }
        }

        return dataList;
    }

    public String queryCompanyContributors(String community, String item, String contributeType, String timeRange, String version) {
        String index;
        String queryStr;
        String claIndex;
        String groupField = "company";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryStr = openEuler.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                claIndex = openEuler.getClaCorporationIndex();
                break;
            case "opengauss":
                index = openGauss.getGiteeAllIndex();
                queryStr = openGauss.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                claIndex = openGauss.getClaCorporationIndex();
                break;
            case "openlookeng":
                index = openLookeng.getGiteeAllIndex();
                queryStr = openLookeng.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                claIndex = openLookeng.getClaCorporationIndex();
                break;
            case "mindspore":
                index = mindSpore.getGiteeAllIndex();
                queryStr = mindSpore.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                claIndex = mindSpore.getClaCorporationIndex();
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        try {
            List<String> claCompanys = queryClaCompany(claIndex);
            List<Map<String, String>> companys = getCompanyNameCnEn(companyNameYaml);
            Map<String, String> companyNameCnEn = companys.get(0);
            Map<String, String> companyNameAlCn = companys.get(1);

            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            //获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            ArrayList<JsonNode> dataList = new ArrayList<>();
            HashMap<String, Object> dataMap = new HashMap<>();
            long independent = 0;
//            long partner = 0;
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String company = bucket.get("key").asText();
                long contribute = bucket.get("sum_field").get("value").asLong();

//                if (company.equals("华为合作方")) {
//                    partner += contribute;
//                    continue;
//                }
                if (!claCompanys.contains(company) || contribute == 0 ||
                        company.contains("软通动力") ||
                        company.contains("中软国际") ||
                        company.contains("易宝软件") ||
                        company.contains("华为合作方")) {
                    independent += contribute;
                    continue;
                }
//                if (company.equals("软通动力信息技术（集团）股份有限公司")) {
//                    contribute += partner;
//                }
                String companyCn = companyNameAlCn.getOrDefault(company.trim(), company.trim());
                String companyEn = companyNameCnEn.getOrDefault(company.trim(), companyCn);
                dataMap.put("company_cn", companyCn);
                dataMap.put("company_en", companyEn);
                dataMap.put("contribute", contribute);
                JsonNode resNode = objectMapper.valueToTree(dataMap);
                dataList.add(resNode);
            }
            dataMap.put("company_cn", "个人贡献者");
            dataMap.put("company_en", "independent");
            dataMap.put("contribute", independent);
            JsonNode resNode = objectMapper.valueToTree(dataMap);
            dataList.add(resNode);

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
    }

    public String queryUserContributors(String community, String item, String contributeType, String timeRange) {
        String index;
        String queryStr;
        String groupField = "gitee_id";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryStr = openEuler.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                break;
            case "opengauss":
                index = openGauss.getGiteeAllIndex();
                queryStr = openGauss.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                break;
            case "openlookeng":
                index = openLookeng.getGiteeAllIndex();
                queryStr = openLookeng.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                break;
            case "mindspore":
                index = mindSpore.getGiteeAllIndex();
                queryStr = mindSpore.getAggCountQueryStr(groupField, contributeType, timeRange, community);
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        try {
            List<String> robotUsers = Arrays.asList(robotUser.split(","));

            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            //获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            ArrayList<JsonNode> dataList = new ArrayList<>();
            HashMap<String, Object> dataMap = new HashMap<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String giteeId = bucket.get("key").asText();
                long contribute = bucket.get("sum_field").get("value").asLong();
                if (contribute == 0 || robotUsers.contains(giteeId)) {
                    continue;
                }
                dataMap.put("gitee_id", giteeId);
                dataMap.put("contribute", contribute);
                JsonNode resNode = objectMapper.valueToTree(dataMap);
                dataList.add(resNode);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

    }

    public Map<String, Object> queryContributes(String community, String item) {
        String giteeIndex;
        String claIndex;
        String contributesQueryStr;
        long prs = 0;
        long issues = 0;
        long comments = 0;
        long repos = 0;
        HashMap<String, Object> dataMap = new HashMap<>();
        dataMap.put("prs", prs);
        dataMap.put("issues", issues);
        dataMap.put("comments", comments);
        dataMap.put("repos", repos);

        switch (community.toLowerCase()) {
            case "openeuler":
                giteeIndex = openEuler.getGiteeAllIndex();
                contributesQueryStr = openEuler.getGiteeContributesQueryStr();
                claIndex = openEuler.getClaCorporationIndex();
                break;
            case "opengauss":
                giteeIndex = openGauss.getGiteeAllIndex();
                contributesQueryStr = openGauss.getGiteeContributesQueryStr();
                claIndex = openGauss.getClaCorporationIndex();
                break;
            case "openlookeng":
                giteeIndex = openLookeng.getGiteeAllIndex();
                contributesQueryStr = openLookeng.getGiteeContributesQueryStr();
                claIndex = openLookeng.getClaCorporationIndex();
                break;
            case "mindspore":
                giteeIndex = mindSpore.getGiteeAllIndex();
                contributesQueryStr = mindSpore.getGiteeContributesQueryStr();
                claIndex = mindSpore.getClaCorporationIndex();
                break;
            default:
                return dataMap;
        }

        List<String> companys = queryClaCompany(claIndex);
        Map<String, Integer> communityPartners = getCommunityPartners(communityPartnersYaml);
        Integer otherPartners = communityPartners.getOrDefault(community.toLowerCase(), 0);
        dataMap.put("partners", companys.size() + otherPartners);

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + giteeIndex + "/_search");
            builder.setBody(contributesQueryStr);
            //获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("orgs").get("buckets").elements();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                prs += bucket.get("prs").get("value").asLong();
                issues += bucket.get("issues").get("value").asLong();
                comments += bucket.get("comments").get("value").asLong();
                repos += bucket.get("repos").get("value").asLong();
            }
            dataMap.put("prs", prs);
            dataMap.put("issues", issues);
            dataMap.put("comments", comments);
            dataMap.put("repos", repos);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return dataMap;
    }

    private List<String> queryClaCompany(String index) {
        ArrayList<String> companys = new ArrayList<>();
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody("{\"size\": 10000}");

            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> hits = dataNode.get("hits").get("hits").elements();
            while (hits.hasNext()) {
                JsonNode source = hits.next().get("_source");
                companys.add(source.get("corporation_name").asText());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return companys;
    }

    private List<Map<String, String>> getCompanyNameCnEn(String yamlFile) {
        YamlUtil yamlUtil = new YamlUtil();
        CompanyYaml companies = yamlUtil.readUrlYaml(yamlFile, CompanyYaml.class);
        System.out.println(companies);

        HashMap<String, String> company_enMap = new HashMap<>();
        HashMap<String, String> company_cnMap = new HashMap<>();
        ArrayList<Map<String, String>> res = new ArrayList<>();
        for (CompanyYamlInfo company : companies.getCompanies()) {
            List<String> aliases = company.getAliases();
            String company_en = company.getCompany_en().trim();
            String company_cn = company.getCompany_cn().trim();
            if (aliases != null) {
                for (String alias : aliases) {
                    company_enMap.put(alias, company_en);
                    company_cnMap.put(alias, company_cn);
                }
            }
            company_enMap.put(company.getCompany_cn().trim(), company_en);
        }
        res.add(company_enMap);
        res.add(company_cnMap);
        return res;
    }

    private Map<String, Integer> getCommunityPartners(String yamlFile) {
        YamlUtil yamlUtil = new YamlUtil();
        CommunityPartnersYaml communities = yamlUtil.readUrlYaml(yamlFile, CommunityPartnersYaml.class);
        System.out.println(communities);

        HashMap<String, Integer> resMap = new HashMap<>();
        for (CommunityPartnersYamlInfo community : communities.getCommunity()) {
            int sum = community.getPartners().stream().mapToInt(Integer::intValue).sum();
            resMap.put(community.getName(), sum);
        }
        return resMap;
    }

    public String queryIssueScore(String community, String start_date, String end_date, String item) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();

        String index = "";
        String queryjson = "";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getIssueScoreIndex();
                queryjson = openEuler.getIssueScoreQueryStr();
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
            default:
                return "";
        }

        com.alibaba.fastjson.JSONObject queryjsonObj = JSON.parseObject(queryjson);
        if (StringUtils.isNotBlank(start_date)) {
            queryjsonObj.getJSONObject("query").getJSONObject("bool").getJSONArray("must").getJSONObject(0)
                    .getJSONObject("range").getJSONObject("created_at").fluentPut("gte", start_date);
        }

        if (StringUtils.isNotBlank(end_date)) {
            queryjsonObj.getJSONObject("query").getJSONObject("bool").getJSONArray("must").getJSONObject(0)
                    .getJSONObject("range").getJSONObject("created_at").fluentPut("lte", end_date);
        }
        queryjson = queryjsonObj.toJSONString();

        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        //获取执行结果
        ListenableFuture<Response> futureRes = client.executeRequest(builder.build());
        return parseIssueScoreFutureRes(futureRes, item);
    }

    private String parseIssueScoreFutureRes(ListenableFuture<Response> futureRes, String dataflage) {
        Response response = null;
        String statusText = "请求内部错误";
        int statusCode = 500;
        String data = null;
        String result = null;
        double count = 0d;
        try {
            response = futureRes.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();

            if (statusCode != 200) {
                data = "[]";
                result = "{\"code\":" + statusCode + ",\"data\":" + data + ",\"msg\":\"" + statusText + "\"}";
                return result;
            }
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            JsonNode records = dataNode.get("aggregations").get("group_by_user_login").get("buckets");
            int totalCount = records.size();

            JSONArray resJsonArray = new JSONArray();
            for (JsonNode record : records) {
                String issue_author = record.get("key").asText();
                Double issue_score = record.get("sum_of_score").get("value").asDouble();

                JSONObject recordJsonObj = new JSONObject();
                recordJsonObj.put("issue_author", issue_author);
                recordJsonObj.put("issue_score", issue_score);
                resJsonArray.put(recordJsonObj);

            }
            result = "{\"code\":" + statusCode + ",\"data\":" + resJsonArray + ",\"msg\":\"" + statusText + "\"}";
            return result;
        } catch (InterruptedException | JsonProcessingException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return "{\"code\":" + statusCode + ",\"data\":\"[]\",\"msg\":\"" + statusText + "\"}";
    }


}
