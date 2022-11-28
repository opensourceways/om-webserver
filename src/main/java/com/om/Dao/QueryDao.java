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

package com.om.Dao;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.om.Modules.*;
import com.om.Modules.yaml.CommunityPartnersYaml;
import com.om.Modules.yaml.CommunityPartnersYamlInfo;
import com.om.Modules.yaml.CompanyYaml;
import com.om.Modules.yaml.CompanyYamlInfo;
import com.om.Modules.yaml.GroupYamlInfo;
import com.om.Modules.yaml.SigYaml;
import com.om.Modules.yaml.SigYamlInfo;
import com.om.Modules.yaml.UserInfoYaml;
import com.om.Modules.yaml.UserNameYaml;
import com.om.Utils.*;
import com.om.Vo.*;
import io.netty.util.internal.StringUtil;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.util.Lists;
import org.asynchttpclient.*;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.index.query.*;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.SortOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;



import static com.alibaba.fastjson.JSON.parseObject;
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

    @Value("${meeting.esurl}")
    String meeting_url;

    @Value("${meeting.userpass}")
    String meeting_userpass;

    @Value("${company.name.yaml}")
    String companyNameYaml;

    @Value("${company.name.local.yaml}")
    String companyNameLocalYaml;

    @Value("${community.partners.yaml}")
    String communityPartnersYaml;

    @Value("${skip.robot.user}")
    String robotUser;

    @Value("${producer.topic.tracker}")
    String topicTracker;

    @Autowired
    KafkaDao kafkaDao;

    @Autowired
    ObsDao obsDao;

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

    public HashMap<String, HashMap<String, String>> getcommunityFeature(String community) {
        String yamlFile;
        switch (community.toLowerCase()) {
            case "openeuler":
                yamlFile = openEuler.getSigsFeature();
                break;
            case "opengauss":
                yamlFile = openGauss.getSigsFeature();
                break;
            default:
                return null;
        }

        YamlUtil yamlUtil = new YamlUtil();
        SigYaml res = yamlUtil.readUrlYaml(yamlFile, SigYaml.class);

        List<GroupYamlInfo> features = res.getFeatures();
        HashMap<String, HashMap<String, String>> resData = new HashMap<>();
        for (GroupYamlInfo feature : features) {
            String group = feature.getgroup();
            String en_group = feature.getEngroup();
            List<SigYamlInfo> groupInfo = feature.getgroup_list();
            for (SigYamlInfo item : groupInfo) {
                List<String> sigs = item.getSigs();
                for (String sig : sigs) {
                    HashMap<String, String> it = new HashMap<>();
                    String name = item.getName();
                    String en_name = item.getEnName();
                    it.put("group", group);
                    it.put("feature", name);
                    it.put("en_group", en_group);
                    it.put("en_feature", en_name);
                    resData.put(sig, it);
                }
            }
        }
        return resData;
    }

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
                    String users = getBucketCount(f, "contributors");
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
        String contributors = getBucketCount(f, "contributors");
        return contributors;
    }

    private String getBucketCount(ListenableFuture<Response> f, String dataFlag) {
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
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("distinct_field").get("buckets").elements();
            count = Lists.newArrayList(buckets).size();
            return "{\"code\":" + statusCode + ",\"data\":{\"" + dataFlag + "\":" + Math.round(count) + "},\"msg\":\"" + statusText + "\"}";
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataFlag + "\":" + count + "},\"msg\":\"" + statusText + "\"}";
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

                // String[] indexs = index.split(";");
                String[] queryjsons = queryjson.split(";");
                double user_count = 0d;
                int statusCode = 500;
                String statusText = "请求内部错误";
                for (int i = 0; i < queryjsons.length; i++) {
                    // index = indexs[i];
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
        contributes.put("contributors", contributorsNode.intValue());
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
        resMap.put("update_at", (new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX")).format(new Date()));
        return objectMapper.valueToTree(resMap).toString();
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
        } catch (Exception e) {
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

    public String queryDownload(String community, String item) throws NoSuchAlgorithmException, KeyManagementException,
            ExecutionException, InterruptedException, JsonProcessingException {
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();
        String index = "";
        String queryjson = "";
        String valueField = "";

        int count = 0;
        int statusCode = 500;
        String statusText = "请求内部错误";

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
                break;
            default:
                return "";
        }
        builder.setUrl(this.url + index + "/_search");
        builder.setBody(queryjson);
        // 获取执行结果
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        try {
            Response response = f.get();
            statusCode = response.getStatusCode();
            statusText = response.getStatusText();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_by_field").get("buckets").elements();
            if (community.toLowerCase().equals("mindspore") && buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                count = bucket.get("count").get("value").asInt();
            }
            if (community.toLowerCase().equals("opengauss") && buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                count = bucket.get("doc_count").asInt();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "{\"code\":" + statusCode + ",\"data\":{\"" + item + "\":" + count + "},\"msg\":\"" + statusText
                + "\"}";

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
                Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_by_field").get("buckets")
                        .elements();
                while (buckets.hasNext()) {
                    JsonNode bucket = buckets.next();
                    count += bucket.get("sum").get("value").asLong();
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return "{\"code\":" + statusCode + ",\"data\":{\"" + dataflage + "\":" + count + "},\"msg\":\"" + statusText
                + "\"}";
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
        EsQueryUtils esQueryUtils = new EsQueryUtils();
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
        HashMap<String, HashSet<String>> id2emails = esQueryUtils.queryBlueUserEmails(restHighLevelClient, index);

        for (BlueZoneUser user : users) {
            String id;
            if (StringUtils.isNotBlank(user.getGitee_id())) id = user.getGitee_id();
            else if (StringUtils.isNotBlank(user.getGithub_id())) id = user.getGithub_id();
            else continue;

            Map resMap = objectMapper.convertValue(user, Map.class);
            resMap.put("created_at", nowStr);
            String email = user.getEmail();
            List<String> inputEmails = Arrays.asList(email.split(";"));

            HashSet<String> emails = id2emails.getOrDefault(id, new HashSet<>());
            emails.addAll(inputEmails);
            ArrayList<String> newEmails = new ArrayList<>(emails);

            if (id2emails.containsKey(id)) {
                HashSet<String> originalEmails = id2emails.get(id);
                originalEmails.addAll(inputEmails);
            }
            resMap.put("emails", newEmails);
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
//        request.add(new IndexRequest("new_year_" + item, "_doc", id).source(indexMap));
        request.add(new IndexRequest("version_" + item, "_doc", id).source(indexMap));
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
                break;
            case "opengauss":
            case "openlookeng":
                indexName = openLookeng.getBug_questionnaire_index();
                break;
            case "mindspore":
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        if (indexName == null) {
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"indexname is null\"}";
        }
        indexName = indexName.substring(1);

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
//            ArrayList<JsonNode> dataList = getObsDetails(indexName, packageQueryjson, queryjson, branch, limit);
            ArrayList<JsonNode> dataList = getObsDetails(indexName, branch, queryjson);
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

    public ArrayList<JsonNode> getObsDetails(String index, String branch, String obsDetailsQueryStr) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        // 1、获取某个工程下的所有包
        AsyncHttpClient client = AsyncHttpUtil.getClient();
        RequestBuilder builder = asyncHttpUtil.getBuilder();

        builder.setUrl(this.url + index + "/_search");
        builder.setBody(String.format(obsDetailsQueryStr, branch));
        ListenableFuture<Response> f = client.executeRequest(builder.build());
        String responseBody = f.get().getResponseBody(UTF_8);
        JsonNode dataNode = objectMapper.readTree(responseBody);
        JsonNode hits = dataNode.get("hits").get("hits");
        Iterator<JsonNode> it = hits.elements();

        ArrayList<JsonNode> dataList = new ArrayList<>();
        while (it.hasNext()) {
            JsonNode hit = it.next();
            JsonNode source = hit.get("_source");
            HashMap<String, Object> packageMap = new HashMap<>();
            packageMap.put("repo_name", source.get("package").asText());
            packageMap.put("obs_version", source.get("versrel").asText());
            packageMap.put("architecture", source.get("hostarch").asText());
            packageMap.put("obs_branch", source.get("project").asText());
            packageMap.put("build_state", source.get("code").asText());

            ArrayList<Long> buildTimes = new ArrayList<>();
            buildTimes.add(source.get("duration").asLong());
            packageMap.put("history_build_times", buildTimes);

            JsonNode resNode = objectMapper.valueToTree(packageMap);
            dataList.add(resNode);
        }

        return dataList;
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
        String[] hostArchs = new String[]{"x86_64", "aarch64"};
        while (packages.hasNext()) {
            String packageName = packages.next().get("key").asText();
            for (String hostarch : hostArchs) {
                builder.setBody(String.format(obsDetailsQueryStr, branch, packageName, hostarch, size));
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
                    maintainers.add(new SigDetailsMaintainer(giteeIdStr, emailStr));
                }
            } else {
                Iterator<JsonNode> jsonNodes = source.get("maintainers").elements();
                while (jsonNodes.hasNext()) {
                    JsonNode maintainer = jsonNodes.next();
                    maintainers.add(new SigDetailsMaintainer(maintainer.textValue(), ""));
                }
            }

            ArrayList<String> repos = new ArrayList<>();
            Iterator<JsonNode> repoNodes = source.get("repos").elements();
            while (repoNodes.hasNext()) {
                JsonNode repo = repoNodes.next();
                repos.add(repo.textValue());
            }
            String description = source.get("description") == null ? "" : source.get("description").asText();

            sig.setName(source.get("sig_name").asText());
            sig.setDescription(description);
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

    public String queryCompanyContributors(String community, String item, String contributeType, String timeRange, String repo, String sig) {
        String index;
        String queryStr;
        String claIndex;
        String groupField = "company";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryStr = openEuler.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                claIndex = openEuler.getClaCorporationIndex();
                break;
            case "opengauss":
                if (null != sig)
                    sig = querySiglabel(community, sig);
                index = openGauss.getGiteeAllIndex();
                queryStr = openGauss.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                claIndex = openGauss.getClaCorporationIndex();
                break;
            case "openlookeng":
                index = openLookeng.getGiteeAllIndex();
                queryStr = openLookeng.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                claIndex = openLookeng.getClaCorporationIndex();
                break;
            case "mindspore":
                index = mindSpore.getGiteeAllIndex();
                queryStr = mindSpore.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                claIndex = mindSpore.getClaCorporationIndex();
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        try {
            List<String> claCompanys = queryClaCompany(claIndex);
            List<Map<String, String>> companys = getCompanyNameCnEn(companyNameYaml, companyNameLocalYaml);
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
//                        company.contains("软通动力") ||
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

    public String queryUserContributors(String community, String item, String contributeType, String timeRange, String repo) {
        String index;
        String queryStr;
        String groupField = "gitee_id";
        String sig = null;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryStr = openEuler.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                break;
            case "opengauss":
                index = openGauss.getGiteeAllIndex();
                queryStr = openGauss.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                break;
            case "openlookeng":
                index = openLookeng.getGiteeAllIndex();
                queryStr = openLookeng.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
                break;
            case "mindspore":
                index = mindSpore.getGiteeAllIndex();
                queryStr = mindSpore.getAggCountQueryStr(groupField, contributeType, timeRange, community, repo, sig);
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

        Map<String, Integer> communityPartners = getCommunityPartners(communityPartnersYaml);
        Integer otherPartners = communityPartners.getOrDefault(community.toLowerCase(), 0);
        try {
            List<String> companys = queryClaCompany(claIndex);
            dataMap.put("partners", companys.size() + otherPartners);
        } catch (Exception ex) {
            dataMap.put("partners", otherPartners);
            ex.printStackTrace();
        }

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

    private List<String> queryClaCompany(String index) throws NoSuchAlgorithmException, KeyManagementException, ExecutionException, InterruptedException, JsonProcessingException {
        ArrayList<String> companys = new ArrayList<>();
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

        return companys;
    }

    private List<Map<String, String>> getCompanyNameCnEn(String yamlFile, String localYamlPath) throws Exception {
        YamlUtil yamlUtil = new YamlUtil();
        String localFile = yamlUtil.wget(yamlFile, localYamlPath);
        CompanyYaml companies = yamlUtil.readLocalYaml(localFile, CompanyYaml.class);
        // System.out.println(companies);

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
        // System.out.println(communities);

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
                index = openLookeng.getIssueScoreIndex();
                queryjson = openLookeng.getIssueScoreQueryStr();
                break;
            case "mindspore":
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
            default:
                return "";
        }

        JSONObject queryjsonObj = parseObject(queryjson);
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
                resJsonArray.fluentAdd(recordJsonObj);
            }
            result = "{\"code\":" + statusCode + ",\"data\":" + resJsonArray + ",\"msg\":\"" + statusText + "\"}";
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "{\"code\":" + statusCode + ",\"data\":\"[]\",\"msg\":\"" + statusText + "\"}";
    }

    public String queryBuildCheckInfo(BuildCheckInfoQueryVo queryBody, String item, Environment env) {

        String communityName = queryBody.getCommunity_name();

        String result = null;
        String resultInfo = null;
        String buildCheckInfoResultIndex;
        String buildCheckInfoMistakeIndex;


        switch (communityName.toLowerCase()) {
            case "openeuler":
                buildCheckInfoResultIndex = openEuler.getBuildCheckResultIndex();
                buildCheckInfoMistakeIndex = openEuler.getBuildCheckMistakeIndex();
                break;
            case "opengauss":
            case "openlookeng":
            case "mindspore":
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
            default:
                return result;
        }

        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        EsQueryUtils esQueryUtils = new EsQueryUtils();

        SearchSourceBuilder queryResultSourceBuilder = assembleResultSourceBuilder("update_at", queryBody);
        resultInfo = esQueryUtils.esScroll(restHighLevelClient, item, buildCheckInfoResultIndex, 5000, queryResultSourceBuilder);
        JSONObject resultJsonObject = parseObject(resultInfo);
        JSONArray resultJsonArray = resultJsonObject.getJSONArray("data");

        JSONArray finalResultJSONArray;
        try {
            finalResultJSONArray = new JSONArray();
            JSONArray empty_ci_mistake_list = new JSONArray();
            int resultTotalCount = resultJsonArray.size();
            for (int i = 0; i < resultTotalCount; i++) {
                JSONObject eachResultJsonObject = (JSONObject) resultJsonArray.get(i);
                String pr_url = eachResultJsonObject.getString("pr_url");
                String build_no = eachResultJsonObject.getString("build_no");
                String result_update_at = eachResultJsonObject.getString("update_at");
                eachResultJsonObject.fluentPut("result_update_at", result_update_at);
                eachResultJsonObject.fluentRemove("update_at");

                SearchSourceBuilder mistakeSourceBuilder = assembleMistakeSourceBuilder("update_at", pr_url, build_no, queryBody);
                String mistakeInfoStr = esQueryUtils.esScroll(restHighLevelClient, item, buildCheckInfoMistakeIndex, 5000, mistakeSourceBuilder);
                JSONObject eachResultMistakeInfoObj = parseObject(mistakeInfoStr);
                JSONArray eachResultMistakeDataJsonArray = eachResultMistakeInfoObj.getJSONArray("data");

                if (eachResultMistakeDataJsonArray.size() < 1) {
                    eachResultJsonObject.fluentPut("ci_mistake_update_at", result_update_at);
                    eachResultJsonObject.fluentPut("ci_mistake", empty_ci_mistake_list);
                } else {
                    String mistakeLatestUpdateTime = getMistakeLatestUpdateTime(eachResultMistakeDataJsonArray);
                    eachResultJsonObject.fluentPut("ci_mistake_update_at", mistakeLatestUpdateTime);
                    eachResultJsonObject.fluentPut("ci_mistake", eachResultMistakeDataJsonArray);
                }


                boolean isAdd = isLocatedInTimeWindow(queryBody, eachResultJsonObject.getString("ci_mistake_update_at"));
                if (!isAdd) {
                    continue;
                }
                finalResultJSONArray.add(eachResultJsonObject);
            }
        } finally {
            try {
                restHighLevelClient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }


        return "{\"code\":200,\"totalCount\":" + finalResultJSONArray.size() + ",\"msg\":\"ok\",\"data\":" + finalResultJSONArray + "}";
    }

    public String getMistakeLatestUpdateTime(JSONArray dateJsonArray) {
        SimpleDateFormat simpleDateFormatWithTimeZone = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        Calendar c = Calendar.getInstance();
        c.clear();
        c.setTimeZone(TimeZone.getTimeZone("Asia/Shanghai"));
        c.set(2000, 00 /* 1月 */, 01, 0, 0, 0);
        Date latestUpdateTime = c.getTime();

        int size = dateJsonArray.size();
        for (int i = 0; i < size; i++) {
            JSONObject eachMistakeJsonObject = dateJsonArray.getJSONObject(i);
            String mistakeUpdateAtStr = String.valueOf(eachMistakeJsonObject.get("update_at"));
            Date currentMistakeUpdateAt = null;
            try {
                currentMistakeUpdateAt = simpleDateFormatWithTimeZone.parse(mistakeUpdateAtStr);
            } catch (ParseException e) {
                e.printStackTrace();
            }

            if (latestUpdateTime.compareTo(currentMistakeUpdateAt) < 0) {
                latestUpdateTime = currentMistakeUpdateAt;
            }
        }
        return simpleDateFormatWithTimeZone.format(latestUpdateTime);
    }

    public SearchSourceBuilder assembleResultSourceBuilder(String sortKeyword,
                                                           BuildCheckInfoQueryVo buildCheckInfoQueryVo) {
        SearchSourceBuilder builder = new SearchSourceBuilder();
        builder.sort(sortKeyword, SortOrder.DESC);

        String pr_url = buildCheckInfoQueryVo.getPr_url();
        String pr_title = buildCheckInfoQueryVo.getPr_title();
        String pr_committer = buildCheckInfoQueryVo.getPr_committer();
        String pr_branch = buildCheckInfoQueryVo.getPr_branch();
        String build_no = buildCheckInfoQueryVo.getBuild_no();
        String check_total = buildCheckInfoQueryVo.getCheck_total();
        Map<String, String> build_duration = buildCheckInfoQueryVo.getBuild_duration();
        Map<String, String> pr_create_time = buildCheckInfoQueryVo.getPr_create_time();
        Map<String, String> result_update_time = buildCheckInfoQueryVo.getResult_update_time();
        Map<String, String> result_build_time = buildCheckInfoQueryVo.getResult_build_time();
        Map<String, String> mistake_update_time = buildCheckInfoQueryVo.getMistake_update_time();

        String min_duration_time = build_duration.get("min_duration_time");
        String max_duration_time = build_duration.get("max_duration_time");
        String pr_create_start_time = pr_create_time.get("start_time");
        String pr_create_end_time = pr_create_time.get("end_time");
        String result_update_start_time = result_update_time.get("start_time");
        String result_update_end_time = result_update_time.get("end_time");
        String result_build_start_time = result_build_time.get("start_time");
        String result_build_end_time = result_build_time.get("end_time");
        String mistake_update_start_time = mistake_update_time.get("start_time");
        String mistake_update_end_time = mistake_update_time.get("end_time");

        TermQueryBuilder termPrUrlQueryBuilder = null;
        TermQueryBuilder termPrTitleQueryBuilder = null;
        TermQueryBuilder termPrCommitterQueryBuilder = null;
        TermQueryBuilder termPrBranchQueryBuilder = null;
        TermQueryBuilder termBuildNoQueryBuilder = null;
        TermQueryBuilder termCheckTotalQueryBuilder = null;
        RangeQueryBuilder rangeBuildTimeQueryBuilder = null;
        RangeQueryBuilder rangePrCreateTimeQueryBuilder = null;
        RangeQueryBuilder rangeResultUpdateTimeQueryBuilder = null;
        RangeQueryBuilder rangeResultBuildTimeQueryBuilder = null;

        if (!StringUtil.isNullOrEmpty(pr_url))
            termPrUrlQueryBuilder = QueryBuilders.termQuery("pr_url.keyword", pr_url);
        if (!StringUtil.isNullOrEmpty(pr_title))
            termPrTitleQueryBuilder = QueryBuilders.termQuery("pr_title.keyword", pr_title);
        if (!StringUtil.isNullOrEmpty(pr_committer))
            termPrCommitterQueryBuilder = QueryBuilders.termQuery("pr_committer.keyword", pr_committer);
        if (!StringUtil.isNullOrEmpty(pr_branch))
            termPrBranchQueryBuilder = QueryBuilders.termQuery("pr_branch.keyword", pr_branch);
        if (!StringUtil.isNullOrEmpty(build_no))
            termBuildNoQueryBuilder = QueryBuilders.termQuery("build_no", Long.parseLong(build_no));
        if (!StringUtil.isNullOrEmpty(check_total))
            termCheckTotalQueryBuilder = QueryBuilders.termQuery("check_total.keyword", check_total);
        if (!StringUtil.isNullOrEmpty(min_duration_time)) {
            rangeBuildTimeQueryBuilder = QueryBuilders.rangeQuery("build_time").gte(min_duration_time);
        }
        if (!StringUtil.isNullOrEmpty(max_duration_time)) {
            rangeBuildTimeQueryBuilder = rangeBuildTimeQueryBuilder.lte(max_duration_time);
        }

        if (!StringUtil.isNullOrEmpty(pr_create_start_time)) {
            rangePrCreateTimeQueryBuilder = QueryBuilders.rangeQuery("pr_create_at").gte(pr_create_start_time)
                    .format("yyyy-MM-dd HH:mm:ss");
        }
        if (!StringUtil.isNullOrEmpty(pr_create_end_time)) {
            rangePrCreateTimeQueryBuilder = rangePrCreateTimeQueryBuilder.lte(pr_create_end_time)
                    .format("yyyy-MM-dd HH:mm:ss");
        }

        if (!StringUtil.isNullOrEmpty(result_update_start_time)) {
            rangeResultUpdateTimeQueryBuilder = QueryBuilders.rangeQuery("update_at").gte(result_update_start_time)
                    .format("yyyy-MM-dd HH:mm:ss");
        }
        if (!StringUtil.isNullOrEmpty(result_update_end_time)) {
            rangeResultUpdateTimeQueryBuilder = rangeResultUpdateTimeQueryBuilder.lte(result_update_end_time)
                    .format("yyyy-MM-dd HH:mm:ss");
        }

        if (!StringUtil.isNullOrEmpty(result_build_start_time)) {
            rangeResultBuildTimeQueryBuilder = QueryBuilders.rangeQuery("build_at").gte(result_build_start_time)
                    .format("yyyy-MM-dd HH:mm:ss");
        }
        if (!StringUtil.isNullOrEmpty(result_build_end_time)) {
            rangeResultBuildTimeQueryBuilder = rangeResultBuildTimeQueryBuilder.lte(result_build_end_time)
                    .format("yyyy-MM-dd HH:mm:ss");
        }

        BoolQueryBuilder mustQuery = QueryBuilders.boolQuery();

        if (termPrUrlQueryBuilder != null) mustQuery = mustQuery.must(termPrUrlQueryBuilder);
        if (termPrTitleQueryBuilder != null) mustQuery = mustQuery.must(termPrTitleQueryBuilder);
        if (termPrCommitterQueryBuilder != null) mustQuery = mustQuery.must(termPrCommitterQueryBuilder);
        if (termPrBranchQueryBuilder != null) mustQuery = mustQuery.must(termPrBranchQueryBuilder);
        if (termBuildNoQueryBuilder != null) mustQuery = mustQuery.must(termBuildNoQueryBuilder);
        if (termCheckTotalQueryBuilder != null) mustQuery = mustQuery.must(termCheckTotalQueryBuilder);

        if (rangeBuildTimeQueryBuilder != null)
            mustQuery = mustQuery.must(rangeBuildTimeQueryBuilder);
        if (rangePrCreateTimeQueryBuilder != null)
            mustQuery = mustQuery.must(rangePrCreateTimeQueryBuilder);
        if (rangeResultUpdateTimeQueryBuilder != null)
            mustQuery = mustQuery.must(rangeResultUpdateTimeQueryBuilder);
        if (rangeResultBuildTimeQueryBuilder != null)
            mustQuery = mustQuery.must(rangeResultBuildTimeQueryBuilder);

        builder.query(mustQuery);
        return builder;
    }

    public SearchSourceBuilder assembleMistakeSourceBuilder(String sortKeyword, String prUrl, String buildNoStr,
                                                            BuildCheckInfoQueryVo buildCheckInfoQueryVo) {
        SearchSourceBuilder builder = new SearchSourceBuilder();
        builder.sort(sortKeyword, SortOrder.DESC);

        TermQueryBuilder prUrlTermQueryBuilder = QueryBuilders.termQuery("pr_url.keyword", prUrl);
        TermQueryBuilder buildNoTermQueryBuilder = QueryBuilders.termQuery("build_no", Long.parseLong(buildNoStr));
        BoolQueryBuilder mustQuery = QueryBuilders.boolQuery().must(prUrlTermQueryBuilder).must(buildNoTermQueryBuilder);

        builder.query(mustQuery);
        return builder;
    }

    private boolean isLocatedInTimeWindow(BuildCheckInfoQueryVo buildCheckInfoQueryVo, String resultMistakeLatestTimeStr) {
        boolean justifiedResult = false;
        SimpleDateFormat simpleDateFormatWithTimeZone = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        String DEFAULT_START_TIME = "2000-01-01 00:00:00";
        String DEFAULT_END_TIME = "2100-01-01 00:00:00";
        String mistakeUpdateStartTimeStr = buildCheckInfoQueryVo.getMistake_update_time().get("start_time");
        String mistakeUpdateEndTimeStr = buildCheckInfoQueryVo.getMistake_update_time().get("end_time");
        if (StringUtil.isNullOrEmpty(mistakeUpdateStartTimeStr)) {
            mistakeUpdateStartTimeStr = DEFAULT_START_TIME;
        }
        if (StringUtil.isNullOrEmpty(mistakeUpdateEndTimeStr)) {
            mistakeUpdateEndTimeStr = DEFAULT_END_TIME;
        }

        Date resultMistakeLatestTime = null;
        Date mistakeUpdateStartTime = null;
        Date mistakeUpdateEndTime = null;
        try {
            resultMistakeLatestTime = simpleDateFormatWithTimeZone.parse(resultMistakeLatestTimeStr);
            mistakeUpdateStartTime = simpleDateFormat.parse(mistakeUpdateStartTimeStr);
            mistakeUpdateEndTime = simpleDateFormat.parse(mistakeUpdateEndTimeStr);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        assert resultMistakeLatestTime != null;
        if (resultMistakeLatestTime.compareTo(mistakeUpdateStartTime) >= 0 &&
                resultMistakeLatestTime.compareTo(mistakeUpdateEndTime) <= 0) {
            justifiedResult = true;
        }
        return justifiedResult;
    }

    public String putUserActionsinfo(String community, String data, Environment env)
            throws NoSuchAlgorithmException, KeyManagementException, IOException {
        String index;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getTracker_index();
                break;
            case "opengauss":
                index = openGauss.getTracker_index();
                break;
            case "mindspore":
                index = mindSpore.getTracker_index();
                break;
            case "openlookeng":
                index = openLookeng.getTracker_index();
                break;
            case "test":
                index = "test_tracker";
                break;
            default:
                return "{\"code\":" + 404 + ",\"data\":\"index: error!\",\"msg\":\"not Found!\"}";
        }
        /*String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        BulkRequest request = new BulkRequest();*/

        String sdata = new String(Base64.getDecoder().decode(data));
        JsonNode userVo = objectMapper.readTree(sdata);
        Date now = new Date();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        String nowStr = simpleDateFormat.format(now);
        String id = userVo.get("_track_id").asText();

        HashMap<String, Object> resMap = objectMapper.convertValue(userVo, HashMap.class);
        resMap.put("created_at", nowStr);
        resMap.put("community", community);

        kafkaDao.sendMess(topicTracker, id, objectMapper.valueToTree(resMap).toString());

        /*request.add(new IndexRequest(index, "_doc", id).source(resMap));
        if (request.requests().size() != 0){
            System.out.println(community);
            System.out.println(resMap);
            restHighLevelClient.bulk(request, RequestOptions.DEFAULT);
        }         
        restHighLevelClient.close();*/

        String res = "{\"code\":200,\"track_id\":" + id + ",\"msg\":\"collect over\"}";
        return res;
    }

    public String querySigName(String community) {
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            String index = "";
            String queryjson = "";
            switch (community.toLowerCase()) {
                case "openeuler":
                    index = openEuler.getSigs_index();
                    queryjson = openEuler.getSigNameQueryStr();
                    break;
                case "opengauss":
                    index = openGauss.getSigs_index();
                    queryjson = openGauss.getSigNameQueryStr();
                    break;
                default:
                    return "{\"code\":" + 404 + ",\"data\":{\"sigs\":" + 0 + "},\"msg\":\"not Found!\"}";
            }
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryjson);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());

            Response response = f.get();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("sig_names").get("buckets").elements();
            HashMap<String, Object> dataMap = new HashMap<>();
            ArrayList<String> sigList = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String sig = bucket.get("key").asText();
                sigList.add(sig);
            }
            dataMap.put(community, sigList);

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataMap);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySigInfo(String community, String sig) {
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            String index = "";
            String queryjson = "";
            switch (community.toLowerCase()) {
                case "openeuler":
                    index = openEuler.getSigs_index();
                    queryjson = openEuler.getSigInfoQueryStr();
                    break;
                case "opengauss":
                    index = openGauss.getSigs_index();
                    queryjson = openGauss.getSigInfoQueryStr();
                    break;
                default:
                    return "{\"code\":" + 404 + ",\"data\":{\"sigs\":" + 0 + "},\"msg\":\"not Found!\"}";
            }
            sig = sig == null ? "*" : sig;
            String querystr = String.format(queryjson, sig);
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(querystr);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());

            Response response = f.get();
            String responseBody = response.getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            Iterator<JsonNode> buckets = dataNode.get("hits").get("hits").elements();
            ArrayList<HashMap<String, Object>> sigList = new ArrayList<>();

            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next().get("_source");
                HashMap<String, Object> data = objectMapper.convertValue(bucket, HashMap.class);
                sigList.add(data);
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", sigList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySigRepo(String community, String sig) {
        String index;
        String queryStr;
        sig = sig == null ? "*" : sig;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getSigs_index();
                queryStr = openEuler.getAggSigRepoQueryStr(sig);
                break;
            case "opengauss":
                index = openGauss.getSigs_index();
                queryStr = openGauss.getAggSigRepoQueryStr(sig);
                break;
            case "openlookeng":
                index = openLookeng.getGiteeAllIndex();
                queryStr = openLookeng.getAggSigRepoQueryStr(sig);
                break;
            case "mindspore":
                index = mindSpore.getSigs_index();
                queryStr = mindSpore.getAggSigRepoQueryStr(sig);
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();
            ArrayList<String> repoList = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String repo = bucket.get("key").asText();
                repoList.add(repo);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", repoList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String queryCompanyName(String community) {
        String index = "";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getClaCorporationIndex();
                break;
            case "opengauss":
                index = openGauss.getClaCorporationIndex();
                break;
            case "mindspore":
                index = mindSpore.getClaCorporationIndex();
                break;
            case "openlookeng":
                return "{\"code\":" + 404 + ",\"data\":{\"companys\":" + 0 + "},\"msg\":\"not Found!\"}";
            default:
                return "";
        }
        try {
            HashMap<String, Object> dataMap = new HashMap<>();
            List<String> companyList = new ArrayList<>();
            companyList = queryClaCompany(index);
            List<Map<String, String>> companys = getCompanyNameCnEn(companyNameYaml, companyNameLocalYaml);
            Map<String, String> companyNameCnEn = companys.get(0);
            Map<String, String> companyNameAlCn = companys.get(1);
            List<HashMap<String, Object>> companyNameList = new ArrayList<>();
            for (String company : companyList) {
                // if (company.contains("软通动力") || company.contains("中软国际") ||
                //         company.contains("易宝软件") || company.contains("华为合作方")) {
                //     continue;
                // }
                HashMap<String, Object> nameMap = new HashMap<>();
                String companyCn = companyNameAlCn.getOrDefault(company.trim(), company.trim());
                String companyEn = companyNameCnEn.getOrDefault(company.trim(), companyCn);
                nameMap.put("company_cn", companyCn);
                nameMap.put("company_en", companyEn);
                companyNameList.add(nameMap);
            }
            dataMap.put(community, companyNameList);

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataMap);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    // 获取企业员工的pr、issue、comment、star、fork、watch等指标
    public String queryCompanyUsercontribute(String community, String company, String timeRange) {
        String index;
        String queryStr;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryStr = openEuler.getAggCompanyUserQueryStr(timeRange, company);
                break;
            case "opengauss":
                index = openGauss.getGiteeAllIndex();
                queryStr = openGauss.getAggCompanyUserQueryStr(timeRange, company);
                break;
            case "openlookeng":
                index = openLookeng.getGiteeAllIndex();
                queryStr = openLookeng.getAggCompanyUserQueryStr(timeRange, company);
                break;
            case "mindspore":
                index = mindSpore.getGiteeAllIndex();
                queryStr = mindSpore.getAggCompanyUserQueryStr(timeRange, company);
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();

            HashMap<String, Object> dataMap = new HashMap<>();
            List<String> metrics = Arrays.asList(new String[]{"PR", "PR_Review", "Issue", "Issue_Comment", "Fork", "Star", "Watch"});
            dataMap.put("metrics", metrics);

            while (buckets.hasNext()) {
                ArrayList<Integer> valueList = new ArrayList<>();
                JsonNode bucket = buckets.next();
                String user = bucket.get("key").asText();
                valueList.add(bucket.get("pr").get("value").asInt());
                valueList.add(bucket.get("review").get("value").asInt());
                valueList.add(bucket.get("issue").get("value").asInt());
                valueList.add(bucket.get("issue_comment").get("value").asInt());
                valueList.add(bucket.get("fork").get("value").asInt());
                valueList.add(bucket.get("star").get("value").asInt());
                valueList.add(bucket.get("watch").get("value").asInt());
                dataMap.put(user, valueList);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataMap);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    // 获取企业员工参与的sig的13个sig活跃度指标
    public String queryCompanySigDetails(String community, String company, String timeRange) {
        String gitee_index;
        String[] queryStrs;
        // String companystr = CompanyCN2Cla(community, company);
        String companystr = getcompanyNames(company);
        switch (community.toLowerCase()) {
            case "openeuler":
                gitee_index = openEuler.getGiteeAllIndex();
                String queryjson = openEuler.getCompanySigsQueryStr();
                queryStrs = openEuler.getAggCompanyGiteeQueryStr(queryjson, timeRange, companystr);
                break;
            default:
                return "{\"code\":400,\"data\":{\"community error\"},\"msg\":\"community error\"}";
        }
        HashMap<String, ArrayList<Integer>> sigMetricsList = commonCompany(gitee_index, queryStrs);
        if (sigMetricsList == null) {
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        Iterator<String> sigAll = sigMetricsList.keySet().iterator();

        HashMap<String, Integer> companyContriList = queryCompanyContribute(community, companystr, timeRange);
        if (companyContriList == null) {
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"queryCompanyContribute error\"}";
        }
        Set<String> sigCon = companyContriList.keySet();
        while (sigAll.hasNext()) {
            String s = sigAll.next();
            if (sigCon.contains(s)) {
                sigMetricsList.get(s).add(companyContriList.get(s));
            } else {
                sigMetricsList.get(s).add(0);
            }
        }

        HashMap<String, ArrayList<Integer>> companyMeetingList = queryCompanyMeetings(community, companystr, timeRange);
        if (companyMeetingList == null) {
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"queryCompanyMeetings error\"}";
        }
        Set<String> sigMeeting = companyMeetingList.keySet();
        sigAll = sigMetricsList.keySet().iterator();
        while (sigAll.hasNext()) {
            String s = sigAll.next();
            if (sigMeeting.contains(s)) {
                ArrayList<Integer> meetingValue = companyMeetingList.get(s);
                sigMetricsList.get(s).add(meetingValue.get(0));
                sigMetricsList.get(s).add(meetingValue.get(1));
            } else {
                sigMetricsList.get(s).add(0);
                sigMetricsList.get(s).add(0);
            }
        }

        HashMap<String, Integer> maintainersList = queryCompanyMaintainers(community, companystr, timeRange);
        if (maintainersList == null) {
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"queryCompanyMaintainers error\"}";
        }
        Set<String> sigMain = maintainersList.keySet();
        sigAll = sigMetricsList.keySet().iterator();
        while (sigAll.hasNext()) {
            String s = sigAll.next();
            if (sigMain.contains(s)) {
                sigMetricsList.get(s).add(maintainersList.get(s));
            } else {
                sigMetricsList.get(s).add(0);
            }
        }

        HashMap<String, Object> dataMap = new HashMap<>();

        ArrayList<HashMap<String, Object>> itemList = new ArrayList<>();
        sigAll = sigMetricsList.keySet().iterator();
        HashMap<String, HashMap<String, String>> sigfeatures = getcommunityFeature(community);
        while (sigAll.hasNext()) {
            HashMap<String, Object> item = new HashMap<>();
            String s = sigAll.next();
            List<Integer> value = sigMetricsList.get(s);
            HashMap<String, String> sigInfo = sigfeatures.get(s);
            String feature = "";
            String group = "";
            String en_feature = "";
            String en_group = "";
            if (sigInfo != null) {
                feature = sigInfo.get("feature");
                group = sigInfo.get("group");
                en_feature = sigInfo.get("en_feature");
                en_group = sigInfo.get("en_group");
            }
            item.put("sig", s);
            item.put("value", value);
            item.put("feature", feature);
            item.put("group", group);
            item.put("en_feature", en_feature);
            item.put("en_group", en_group);
            itemList.add(item);
        }
        List<String> metrics = Arrays.asList(new String[]{"D0", "D1", "D2", "Company", "PR_Merged", "PR_Review", "Issue_update", "Issue_Closed", "Issue_Comment", "Contribute", "Meeting", "Attebdee", "Maintainer"});
        dataMap.put("metrics", metrics);
        dataMap.put(company, itemList);
        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", 200);
        resMap.put("data", dataMap);
        resMap.put("msg", "success");
        return objectMapper.valueToTree(resMap).toString();
    }

    public HashMap<String, ArrayList<Integer>> commonCompany(String index, String[] queryStrs) {
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            HashMap<String, ArrayList<Integer>> sigMap = new HashMap<>();

            for (int i = 0; i < queryStrs.length; i++) {
                // 获取执行结果
                builder.setUrl(this.url + index + "/_search");
                builder.setBody(queryStrs[i]);

                ListenableFuture<Response> f = client.executeRequest(builder.build());
                String responseBody = f.get().getResponseBody(UTF_8);
                JsonNode dataNode = objectMapper.readTree(responseBody);

                Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();

                ArrayList<String> tmp = new ArrayList<>();
                while (buckets.hasNext()) {
                    JsonNode bucket = buckets.next();
                    String sig = bucket.get("key").asText();
                    int value = bucket.get("count").get("value").asInt();
                    ArrayList<Integer> sigMetricsList = new ArrayList<>();
                    for (int j = 0; j < i; j++) {
                        sigMetricsList.add(0);
                    }
                    if (!sigMap.containsKey(sig)) {
                        sigMap.put(sig, sigMetricsList);
                    }
                    sigMap.get(sig).add(value);
                    tmp.add(sig);
                }
                Iterator<String> sigkeys = sigMap.keySet().iterator();
                while (sigkeys.hasNext()) {
                    String key = sigkeys.next();
                    if (!tmp.contains(key)) {
                        sigMap.get(key).add(0);
                    }
                }
            }
            return sigMap;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public HashMap<String, Integer> queryCompanyContribute(String community, String company, String timeRange) {
        String gitee_index;
        String[] queryStrs;
        switch (community.toLowerCase()) {
            case "openeuler":
                gitee_index = openEuler.getGiteeAllIndex();
                String queryjson = openEuler.getCompanyContributeQueryStr();
                queryStrs = openEuler.getAggCompanyGiteeQueryStr(queryjson, timeRange, company);
                break;
            default:
                return null;
        }
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            HashMap<String, Integer> sigMap = new HashMap<>();

            for (int i = 0; i < queryStrs.length; i++) {
                // 获取执行结果
                builder.setUrl(this.url + gitee_index + "/_search");
                builder.setBody(queryStrs[i]);

                ListenableFuture<Response> f = client.executeRequest(builder.build());
                String responseBody = f.get().getResponseBody(UTF_8);
                JsonNode dataNode = objectMapper.readTree(responseBody);
                Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();
                int count = 0;
                while (buckets.hasNext()) {
                    JsonNode bucket = buckets.next();
                    String sig = bucket.get("key").asText();
                    count = bucket.get("doc_count").asInt();
                    sigMap.put(sig, count);
                }
            }
            return sigMap;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public HashMap<String, ArrayList<Integer>> queryCompanyMeetings(String community, String company, String timeRange) {
        String meeting_index;
        String[] queryStrs;
        switch (community.toLowerCase()) {
            case "openeuler":
                meeting_index = openEuler.getMeetingsIndex();
                String queryjson = openEuler.getCompanyMeetingsQueryStr();
                queryStrs = openEuler.getAggCompanyGiteeQueryStr(queryjson, timeRange, company);
                break;
            default:
                return null;
        }
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder().setHeader("Authorization",
                    "Basic " + Base64.getEncoder().encodeToString((meeting_userpass).getBytes()));
            HashMap<String, ArrayList<Integer>> sigMap = new HashMap<>();

            for (int i = 0; i < queryStrs.length; i++) {
                // 获取执行结果
                builder.setUrl(this.meeting_url + meeting_index + "/_search");
                builder.setBody(queryStrs[i]);

                ListenableFuture<Response> f = client.executeRequest(builder.build());
                String responseBody = f.get().getResponseBody(UTF_8);
                JsonNode dataNode = objectMapper.readTree(responseBody);
                Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();

                while (buckets.hasNext()) {
                    JsonNode bucket = buckets.next();
                    String sig = bucket.get("key").asText();
                    int count = bucket.get("doc_count").asInt();
                    int num = bucket.get("count").get("value").asInt();
                    ArrayList<Integer> meeting = new ArrayList<>();
                    meeting.add(count);
                    meeting.add(num);
                    sigMap.put(sig, meeting);
                }
            }
            return sigMap;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public HashMap<String, Integer> queryCompanyMaintainers(String community, String company, String timeRange) {
        String sig_index;
        String[] queryStrs;
        switch (community.toLowerCase()) {
            case "openeuler":
                sig_index = openEuler.getSigs_index();
                String queryjson = openEuler.getCompanyMaintainersQueryStr();
                queryStrs = openEuler.getAggCompanyGiteeQueryStr(queryjson, timeRange, company);
                break;
            default:
                return null;
        }
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            HashMap<String, Integer> sigMap = new HashMap<>();

            String query = queryStrs[0];
            // 获取执行结果
            builder.setUrl(this.url + sig_index + "/_search");
            builder.setBody(query);

            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String sig = bucket.get("key").asText();
                int value = bucket.get("count").get("value").asInt();
                sigMap.put(sig, value);
            }
            return sigMap;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 获取每个sig的maintainers、committers
    public JsonNode querySigOwnerTypeCount(String community, String sig) {
        String index;
        String queryStr;
        String queryJson;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getSigs_index();
                queryJson = openEuler.getSigOwnerType();
                break;
            case "opengauss":
                index = openGauss.getSigs_index();
                queryJson = openGauss.getSigOwnerType();
                break;
            default:
                System.out.println("{\"code\":400,\"data\":{\"" + sig + "\":\"query error\"},\"msg\":\"query error\"}");
                return null;
        }

        if (queryJson == null) {
            System.out.println("SigUserTypeQueryStr is null...");
            return null;
        }
        queryStr = String.format(queryJson, sig);
        JsonNode resNode = commonOwnerType(index, queryStr);
        return resNode;
    }

    // 获取所有sig的maintainers、committers
    public JsonNode queryOwnerTypeCount(String community, String company) {
        String index;
        String queryJson;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getSigs_index();
                queryJson = openEuler.getAllSigsOwnerType();
                break;
            case "opengauss":
                index = openGauss.getSigs_index();
                queryJson = openGauss.getAllSigsOwnerType();
                break;
            default:
                System.out.println("{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}");
                return null;
        }
        if (queryJson == null) {
            return null;
        }
        String queryStr = String.format(queryJson, company);
        JsonNode resNode = commonOwnerType(index, queryStr);
        return resNode;
    }

    public JsonNode commonOwnerType(String index, String queryStr) {
        try {
            List<String> robotUsers = Arrays.asList(robotUser.split(","));
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            HashMap<String, Object> dataMap = new HashMap<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String giteeId = bucket.get("key").asText();
                Iterator<JsonNode> ownerTypebucket = bucket.get("owner_type").get("buckets").elements();
                String ownerType = "committers";
                while (ownerTypebucket.hasNext()) {
                    JsonNode ownertype = ownerTypebucket.next();
                    ownerType = ownertype.get("key").asText();
                    if (ownerType.equals("maintainers")) {
                        break;
                    }
                }
                if (robotUsers.contains(giteeId)) { // openeuler-basic
                    continue;
                }
                if (dataMap.containsKey(giteeId)
                        && dataMap.get(giteeId).equals("maintainers")) {
                    continue;
                }
                dataMap.put(giteeId, ownerType);

            }
            JsonNode resNode = objectMapper.valueToTree(dataMap);
            return resNode;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}");
            return null;
        }
    }

    public String getcompanyNames(String name) {
        ArrayList<String> res = new ArrayList<>();
        res.add(name);
        YamlUtil yamlUtil = new YamlUtil();
        CompanyYaml companies = yamlUtil.readUrlYaml(companyNameYaml, CompanyYaml.class);
        for (CompanyYamlInfo companyinfo : companies.getCompanies()) {
            String cnCompany = companyinfo.getCompany_cn().trim();
            String enCompany = companyinfo.getCompany_en().trim();
            if (name.equals(cnCompany) || name.equals(enCompany)) {
                res.add(enCompany);
                res.add(cnCompany);
                List<String> aliases = companyinfo.getAliases();
                if (aliases != null) {
                    for (String alias : aliases) {
                        res.add(alias);
                    }
                }
            }
        }
        String names = "(";
        for (String r : res) {
            names = names + "\\\"" + r + "\\\",";
        }
        names = names + ")";
        return names;
    }

    public String CompanyCN2Cla(String community, String company) {
        String resCompany = "";
        YamlUtil yamlUtil = new YamlUtil();
        CompanyYaml companies = yamlUtil.readUrlYaml(companyNameYaml, CompanyYaml.class);
        for (CompanyYamlInfo companyinfo : companies.getCompanies()) {
            String cnCompany = companyinfo.getCompany_cn().trim();
            if (company.equals(cnCompany)) {
                List<String> aliases = companyinfo.getAliases();
                if (aliases != null) {
                    for (String alias : aliases) {
                        if (community.toLowerCase().equals("openeuler")) {
                            resCompany = alias;
                            break;
                        }
                        resCompany = alias;
                    }
                    return resCompany;
                }
                resCompany = cnCompany;
                return resCompany;
            }
        }
        return company;
    }

    // 根据sig或者commpany获取贡献者的pr、issue、comment等指标
    public String queryGroupUserContributors(String community, String group_field, String group, String contributeType, String timeRange) {
        String index;
        String queryStr;
        JsonNode ownerType;
        JsonNode TC_owners = querySigOwnerTypeCount(community, "TC");

        switch (group_field) {
            case "sig":
                ownerType = querySigOwnerTypeCount(community, group);
                break;
            case "company":
                // group = CompanyCN2Cla(community, group);
                group = getcompanyNames(group);
                ownerType = queryOwnerTypeCount(community, group);
                break;
            default:
                return "";
        }

        Iterator<String> users = ownerType.fieldNames();
        HashMap<String, String> data = new HashMap<>();
        while (users.hasNext()) {
            String user = users.next();
            data.put(user.toLowerCase(), ownerType.get(user).asText());
        }
        JsonNode ownerTypeLower = objectMapper.valueToTree(data);

        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryStr = openEuler.getAggGroupCountQueryStr(group_field, group, contributeType, timeRange, community, null);
                break;
            case "opengauss":
                String label = querySiglabel(community, group);
                index = openGauss.getGiteeAllIndex();
                queryStr = openGauss.getAggGroupCountQueryStr(group_field, group, contributeType, timeRange, community, label);
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        if (queryStr == null) {
            return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        try {
            List<String> robotUsers = Arrays.asList(robotUser.split(","));

            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            ArrayList<JsonNode> dataList = new ArrayList<>();
            ArrayList<String> userList = new ArrayList<>();

            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String giteeId = bucket.get("key").asText();
                long contribute = bucket.get("sum_field").get("value").asLong();
                if (contribute == 0 || robotUsers.contains(giteeId)) {
                    continue;
                }
                String userType = "contributor";
                if (ownerTypeLower.has(giteeId.toLowerCase())) {
                    userType = ownerTypeLower.get(giteeId.toLowerCase()).asText();
                }
                HashMap<String, Object> dataMap = new HashMap<>();
                dataMap.put("gitee_id", giteeId);
                dataMap.put("contribute", contribute);
                dataMap.put("usertype", userType);
                if (TC_owners.has(giteeId)) {
                    dataMap.put("is_TC_owner", 1);
                }
                JsonNode resNode = objectMapper.valueToTree(dataMap);
                dataList.add(resNode);
                userList.add(giteeId.toLowerCase());
            }

            Iterator<String> owners = ownerType.fieldNames();
            while (owners.hasNext()) {
                String owner = owners.next();
                if (userList.contains(owner.toLowerCase())) {
                    continue;
                }
                HashMap<String, Object> dataMap = new HashMap<>();
                dataMap.put("gitee_id", owner);
                dataMap.put("contribute", 0);
                dataMap.put("usertype", ownerType.get(owner));
                if (TC_owners.has(owner)) {
                    dataMap.put("is_TC_owner", 1);
                }
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
            return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }

    }

    public String queryCompanyUsers(String community, String company, String timeRange) {
        String queryjsons;
        String index;
        String[] queryStrs;
        // company = CompanyCN2Cla(community,company);
        company = getcompanyNames(company);
        switch (community.toLowerCase()) {
            case "openeuler":
                queryjsons = openEuler.getComapnyUsers();
                queryStrs = openEuler.getAggCompanyGiteeQueryStr(queryjsons, timeRange, company);
                index = openEuler.getGiteeAllIndex();
                break;
            case "opengauss":
                queryjsons = openGauss.getComapnyUsers();
                queryStrs = openGauss.getAggCompanyGiteeQueryStr(queryjsons, timeRange, company);
                index = openGauss.getGiteeAllIndex();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            ArrayList<Integer> companyUsersList = new ArrayList<>();

            for (int i = 0; i < queryStrs.length; i++) {
                // 获取执行结果
                builder.setUrl(this.url + index + "/_search");
                builder.setBody(queryStrs[i]);

                ListenableFuture<Response> f = client.executeRequest(builder.build());
                String responseBody = f.get().getResponseBody(UTF_8);
                JsonNode dataNode = objectMapper.readTree(responseBody);
                int value = dataNode.get("aggregations").get("group_filed").get("value").asInt();
                companyUsersList.add(value);
            }
            HashMap<String, Object> dataMap = new HashMap<>();
            dataMap.put("value", companyUsersList);
            List<String> metrics = Arrays.asList(new String[]{"D0", "D1", "D2"});
            dataMap.put("metrics", metrics);

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataMap);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String queryCommunityRepos(String community) {
        String index;
        String queryStr;
        switch (community.toLowerCase()) {
            case "openeuler":
                queryStr = openEuler.getCommunityRepoQueryStr();
                index = openEuler.getContributors_index();
                break;
            case "opengauss":
                queryStr = openGauss.getCommunityRepoQueryStr();
                index = openGauss.getContributors_index();
                break;
            case "openlookeng":
                queryStr = openLookeng.getCommunityRepoQueryStr();
                index = openLookeng.getContributors_index();
                break;
            case "mindspore":
                queryStr = mindSpore.getCommunityRepoQueryStr();
                index = mindSpore.getContributors_index();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            ArrayList<String> dataList = new ArrayList<>();
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);

            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> hits = dataNode.get("hits").get("hits").elements();
            while (hits.hasNext()) {
                JsonNode hit = hits.next();
                String repository = hit.get("_source").get("repository").asText();
                dataList.add(repository);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySigScore(String community, String sig, String timeRange, String type) {
        String queryjson;
        String index;
        String queryStr;
        switch (community.toLowerCase()) {
            case "openeuler":
                queryjson = openEuler.getsig_score_queryStr();
                queryStr = openEuler.getSigScoreQuery(queryjson, timeRange, sig);
                if (type.equals("radar")) {
                    index = openEuler.getsig_radar_score_index();
                } else {
                    index = openEuler.getsig_score_index();
                }
                break;
            case "opengauss":
                queryjson = openGauss.getsig_score_queryStr();
                queryStr = openGauss.getSigScoreQuery(queryjson, timeRange, sig);
                if (type.equals("radar")) {
                    index = openEuler.getsig_radar_score_index();
                } else {
                    index = openEuler.getsig_score_index();
                }
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);

            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("hits").get("hits").elements();
            ArrayList<HashMap<String, Object>> sigList = new ArrayList<>();
            HashMap<String, HashMap<String, String>> sigfeatures = getcommunityFeature(community);
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next().get("_source");
                HashMap<String, Object> data = objectMapper.convertValue(bucket, HashMap.class);
                HashMap<String, String> sigInfo = sigfeatures.get(sig);
                String feature = "";
                String group = "";
                String en_feature = "";
                String en_group = "";
                if (sigInfo != null) {
                    feature = sigInfo.get("feature");
                    group = sigInfo.get("group");
                    en_feature = sigInfo.get("en_feature");
                    en_group = sigInfo.get("en_group");
                }
                data.put("feature", feature);
                data.put("group", group);
                data.put("en_feature", en_feature);
                data.put("en_group", en_group);
                sigList.add(data);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", sigList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySigScoreAll(String community) {
        String queryjson;
        String index;
        switch (community.toLowerCase()) {
            case "openeuler":
                queryjson = openEuler.getall_sig_score_queryStr();
                index = openEuler.getsig_score_index();
                break;
            case "opengauss":
                // queryjson = openGauss.getall_sig_score_queryStr();
                // index = openEuler.getsig_score_index();
                return getSigGroups(community);
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            Calendar c = Calendar.getInstance();
            c.setTime(new Date());
            c.add(Calendar.DATE, -1);
            String queryStr = String.format(queryjson, c.getTimeInMillis());
            String responseBody = query(index, queryStr);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("hits").get("hits").elements();
            if (!buckets.hasNext()) {
                c.add(Calendar.DATE, -1);
                queryStr = String.format(queryjson, c.getTimeInMillis());
                responseBody = query(index, queryStr);
                dataNode = objectMapper.readTree(responseBody);
                buckets = dataNode.get("hits").get("hits").elements();
            }
            ArrayList<HashMap<String, Object>> sigList = new ArrayList<>();
            HashMap<String, HashMap<String, String>> sigfeatures = getcommunityFeature(community);
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next().get("_source");
                HashMap<String, Object> data = objectMapper.convertValue(bucket, HashMap.class);
                String sig = bucket.get("sig_names").asText();
                HashMap<String, String> sigInfo = sigfeatures.get(sig);
                String feature = "";
                String group = "";
                String en_feature = "";
                String en_group = "";
                if (sigInfo != null) {
                    feature = sigInfo.get("feature");
                    group = sigInfo.get("group");
                    en_feature = sigInfo.get("en_feature");
                    en_group = sigInfo.get("en_group");
                }
                data.put("feature", feature);
                data.put("group", group);
                data.put("en_feature", en_feature);
                data.put("en_group", en_group);
                data.remove("value");
                sigList.add(data);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", sigList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String getSigGroups(String community) {
        HashMap<String, HashMap<String, String>> sigfeatures = getcommunityFeature(community);
        ArrayList<HashMap<String, String>> sigList = new ArrayList<>();
        Set<String> keys = sigfeatures.keySet();
        for (String key : keys) {
            HashMap<String, String> data = sigfeatures.get(key);
            data.put("sig_names", key);
            sigList.add(data);
        }
        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", 200);
        resMap.put("data", sigList);
        resMap.put("msg", "success");
        return objectMapper.valueToTree(resMap).toString();
    }

    public String queryCompanySigs(String community, String timeRange) {
        String queryjson;
        String index;
        String queryStr;
        String claIndex;
        switch (community.toLowerCase()) {
            case "openeuler":
                queryjson = openEuler.getAllCompanySigsQueryStr();
                queryStr = openEuler.getcommonQuery(queryjson, timeRange);
                claIndex = openEuler.getClaCorporationIndex();
                index = openEuler.getGiteeAllIndex();
                break;
            case "opengauss":
                queryjson = openGauss.getAllCompanySigsQueryStr();
                queryStr = openGauss.getcommonQuery(queryjson, timeRange);
                claIndex = openGauss.getClaCorporationIndex();
                index = openGauss.getGiteeAllIndex();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            List<String> claCompanys = queryClaCompany(claIndex);
            List<Map<String, String>> companys = getCompanyNameCnEn(companyNameYaml, companyNameLocalYaml);
            Map<String, String> companyNameCnEn = companys.get(0);
            Map<String, String> companyNameAlCn = companys.get(1);

            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);

            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_filed").get("buckets").elements();
            ArrayList<JsonNode> dataList = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String company = bucket.get("key").asText();
                if (!claCompanys.contains(company) ||
//                        company.contains("软通动力") ||
                        company.contains("中软国际") ||
                        company.contains("易宝软件") ||
                        company.contains("华为合作方")) {
                    continue;
                }
                Iterator<JsonNode> its = bucket.get("sigs").get("buckets").elements();
                ArrayList<String> sigList = new ArrayList<>();
                while (its.hasNext()) {
                    JsonNode it = its.next();
                    sigList.add(it.get("key").asText());
                }
                String companyCn = companyNameAlCn.getOrDefault(company.trim(), company.trim());
                String companyEn = companyNameCnEn.getOrDefault(company.trim(), companyCn);
                HashMap<String, Object> dataMap = new HashMap<>();
                dataMap.put("company_cn", companyCn);
                dataMap.put("company_en", companyEn);
                dataMap.put("sigList", sigList);
                JsonNode resNode = objectMapper.valueToTree(dataMap);
                dataList.add(resNode);
            }

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("msg", "success");
            resMap.put("code", 200);
            resMap.put("data", dataList);
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySigsOfTCOwners(String community) {
        String index;
        String queryJson;
        String yamlFile;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getSigs_index();
                queryJson = openEuler.getuser_owns_sigs_Str();
                yamlFile = openEuler.gettc_owner_url();
                break;
            case "opengauss":
                index = openGauss.getSigs_index();
                queryJson = openGauss.getuser_owns_sigs_Str();
                yamlFile = openGauss.gettc_owner_url();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        JsonNode TC_owners = querySigOwnerTypeCount(community, "TC");
        Map<String, String> userName = getUserNameCnEn(yamlFile);

        Iterator<String> users = TC_owners.fieldNames();
        ArrayList<HashMap<String, Object>> res = new ArrayList<>();
        while (users.hasNext()) {
            String user = users.next();
            String queryStr = String.format(queryJson, user);
            try {
                AsyncHttpClient client = AsyncHttpUtil.getClient();
                RequestBuilder builder = asyncHttpUtil.getBuilder();
                builder.setUrl(this.url + index + "/_search");
                builder.setBody(queryStr);

                ListenableFuture<Response> f = client.executeRequest(builder.build());
                String responseBody = f.get().getResponseBody(UTF_8);
                JsonNode dataNode = objectMapper.readTree(responseBody);
                Iterator<JsonNode> buckets = dataNode.get("aggregations").get("2").get("buckets").elements();
                ArrayList<String> sigList = new ArrayList<>();
                while (buckets.hasNext()) {
                    JsonNode bucket = buckets.next();
                    sigList.add(bucket.get("key").asText());
                }
                HashMap<String, Object> resData = new HashMap<>();
                String user_cn = userName.get(user);
                resData.put("user", user);
                resData.put("name", user_cn);
                resData.put("sigs", sigList);
                res.add(resData);

            } catch (Exception e) {
                e.printStackTrace();
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
            }
        }
        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", 200);
        resMap.put("data", res);
        resMap.put("msg", "success");
        return objectMapper.valueToTree(resMap).toString();
    }

    public Map<String, String> getUserNameCnEn(String yamlFile) {
        YamlUtil yamlUtil = new YamlUtil();
        UserNameYaml users = yamlUtil.readUrlYaml(yamlFile, UserNameYaml.class);

        HashMap<String, String> userMap = new HashMap<>();
        for (UserInfoYaml user : users.getUsers()) {
            String user_en = user.getEn().trim();
            String user_cn = user.getCn().trim();
            userMap.put(user_en, user_cn);
        }
        return userMap;
    }

    public String queryGroupSigcontribute(String community, String group, String group_field, String contributeType, String timeRange) {
        String index;
        String queryjson;
        String queryStr;
        String field;
        switch (group_field) {
            case "user":
                field = "user_login.keyword";
                break;
            case "company":
                // group = CompanyCN2Cla(community, group);
                group = getcompanyNames(group);
                field = "tag_user_company.keyword";
                break;
            default:
                return "";
        }

        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                queryjson = openEuler.getgroup_agg_sig_queryStr();
                queryStr = openEuler.getAggGroupSigCountQueryStr(queryjson, contributeType, timeRange, group, field);
                break;
            case "opengauss":
                index = openGauss.getGiteeAllIndex();
                queryjson = openGauss.getgroup_agg_sig_queryStr();
                queryStr = openGauss.getAggGroupSigCountQueryStr(queryjson, contributeType, timeRange, group, field);
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        if (queryStr == null) {
            return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();

            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            // 获取执行结果
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);

            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();
            double count = 0d;
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                long contribute = bucket.get("sum_field").get("value").asLong();
                count += contribute;
            }

            ArrayList<JsonNode> dataList = new ArrayList<>();
            buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();
            long rank = 1;
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String sig_name = bucket.get("key").asText();
                long contribute = bucket.get("sum_field").get("value").asLong();
                double percent = contribute / count;

                HashMap<String, Object> dataMap = new HashMap<>();
                dataMap.put("sig_name", sig_name);
                dataMap.put("contribute", contribute);
                dataMap.put("percent", percent);
                dataMap.put("rank", rank);
                JsonNode resNode = objectMapper.valueToTree(dataMap);
                dataList.add(resNode);
                rank += 1;
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }
    }

    public String queryUserOwnertype(String community, String user) {
        String queryjson;
        String queryStr;
        String index;

        switch (community.toLowerCase()) {
            case "openeuler":
                queryjson = openEuler.getuser_owner_type_queryStr();
                index = openEuler.getSigs_index();
                break;
            case "opengauss":
                queryjson = openGauss.getuser_owner_type_queryStr();
                index = openGauss.getSigs_index();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        queryStr = String.format(queryjson, user);

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            ArrayList<HashMap<String, Object>> dataMap = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String sig = bucket.get("key").asText();
                Iterator<JsonNode> types = bucket.get("owner_type").get("buckets").elements();
                ArrayList<String> typeList = new ArrayList<>();
                while (types.hasNext()) {
                    JsonNode type = types.next();
                    typeList.add(type.get("key").asText());
                }
                HashMap<String, Object> user_type = new HashMap<>();
                user_type.put("sig", sig);
                user_type.put("type", typeList);
                dataMap.add(user_type);
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataMap);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String queryAllUserOwnertype(String community) {
        String queryStr;
        String index;

        switch (community.toLowerCase()) {
            case "openeuler":
                queryStr = openEuler.getall_user_owner_type_queryStr();
                index = openEuler.getSigs_index();
                break;
            case "opengauss":
                queryStr = openGauss.getall_user_owner_type_queryStr();
                index = openGauss.getSigs_index();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            HashMap<String, ArrayList<Object>> userData = new HashMap<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String sig = bucket.get("key").asText();
                Iterator<JsonNode> users = bucket.get("user").get("buckets").elements();
                while (users.hasNext()) {
                    JsonNode userBucket = users.next();
                    String user = userBucket.get("key").asText();
                    Iterator<JsonNode> types = userBucket.get("type").get("buckets").elements();
                    ArrayList<String> typeList = new ArrayList<>();
                    while (types.hasNext()) {
                        JsonNode type = types.next();
                        typeList.add(type.get("key").asText());
                    }
                    HashMap<String, Object> user_type = new HashMap<>();
                    user_type.put("sig", sig);
                    user_type.put("type", typeList);

                    if (userData.containsKey(user.toLowerCase())) {
                        userData.get(user.toLowerCase()).add(user_type);
                    } else {
                        ArrayList<Object> templist = new ArrayList<>();
                        templist.add(user_type);
                        userData.put(user.toLowerCase(), templist);
                    }
                }
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", userData);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String queryUserContributeDetails(String community, String user, String sig, String contributeType,
                                             String timeRange, Environment env, String comment_type, String filter) {
        String index;
        ArrayList<Object> params;
        String label = null;
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getGiteeAllIndex();
                params = openEuler.getAggUserCountQueryParams(contributeType, timeRange);
                break;
            case "opengauss":
                index = openGauss.getGiteeAllIndex();
                params = openGauss.getAggUserCountQueryParams(contributeType, timeRange);
                if (null != sig)
                    label  = querySiglabel(community, sig);
                break;
            default:
                return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"query error\"}";
        }
        index = index.substring(1);
        if (params == null) {
            return "{\"code\":400,\"data\":{\"" + contributeType + "\":\"query error\"},\"msg\":\"params error\"}";
        }

        String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
        String host = env.getProperty("es.host");
        int port = Integer.parseInt(env.getProperty("es.port", "9200"));
        String scheme = env.getProperty("es.scheme");
        String esUser = userpass[0];
        String password = userpass[1];
        RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
        EsQueryUtils esQueryUtils = new EsQueryUtils();

        return esQueryUtils.esUserCount(community, restHighLevelClient, index, user, sig, params, comment_type, filter, label);
    }

    public String queryUserLists(String community, String group, String name) {
        String queryjson;
        String queryStr;
        String index;
        if (group != null && group.equals("company")) {
            name = getcompanyNames(name);
        }
        switch (community.toLowerCase()) {
            case "openeuler":
                queryjson = openEuler.getUserListQueryStr();
                queryStr = openEuler.getAggUserListQueryStr(queryjson, group, name);
                index = openEuler.getGiteeAllIndex();
                break;
            case "opengauss":
                queryjson = openGauss.getUserListQueryStr();
                queryStr = openGauss.getAggUserListQueryStr(queryjson, group, name);
                index = openGauss.getGiteeAllIndex();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            ArrayList<String> dataMap = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String user = bucket.get("key").asText();
                dataMap.add(user);
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", dataMap);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySigRepoCommitters(String community, String sig) {
        String queryjson;
        String queryStr;
        String index;
        switch (community.toLowerCase()) {
            case "openeuler":
                queryjson = openEuler.getSigRepoCommittersQueryStr();
                index = openEuler.getSigs_index();
                break;
            case "opengauss":
                queryjson = openGauss.getSigRepoCommittersQueryStr();
                index = openGauss.getSigs_index();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        try {
            queryStr = String.format(queryjson, sig);
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            ArrayList<Object> dataList = new ArrayList<>();
            ArrayList<String> committerList = new ArrayList<>();
            ArrayList<String> committerRepoList = new ArrayList<>();

            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String repo = bucket.get("key").asText();
                Iterator<JsonNode> user_buckets = bucket.get("user").get("buckets").elements();
                ArrayList<String> userlist = new ArrayList<>();
                while (user_buckets.hasNext()) {
                    JsonNode userBucket = user_buckets.next();
                    String user = userBucket.get("key").asText();
                    userlist.add(user);
                    committerList.add(user);
                }
                HashMap<String, Object> dataMap = new HashMap<>();
                dataMap.put("repo", repo);
                dataMap.put("gitee_id", userlist);
                dataList.add(dataMap);
                committerRepoList.add(repo);
            }
            Set<String> set = new HashSet<>();
            set.addAll(committerList);
            ArrayList<String> committers = new ArrayList<>();
            committers.addAll(set);

            String res = querySigRepo(community, sig);
            JsonNode resNode = objectMapper.readTree(res);
            if (resNode.get("code").asInt() == 200 && resNode.get("data").size() != 0) {
                Iterator<JsonNode> repos = resNode.get("data").elements();
                while (repos.hasNext()) {
                    String repo = repos.next().asText();
                    if (committerRepoList.contains(repo)) {
                        continue;
                    }
                    HashMap<String, Object> dataMap = new HashMap<>();
                    ArrayList<String> nulllist = new ArrayList<>();
                    dataMap.put("repo", repo);
                    dataMap.put("gitee_id", nulllist);
                    dataList.add(dataMap);
                }
            }

            HashMap<String, Object> resData = new HashMap<>();
            String siginfo = querySigInfo(community, sig);
            JsonNode sigMaintainers = objectMapper.readTree(siginfo).get("data");
            if (sigMaintainers.size() != 0) {
                JsonNode maintainers = sigMaintainers.get(0).get("maintainers");
                resData.put("maintainers", maintainers);
            }
            resData.put("committers", committers);
            resData.put("committerDetails", dataList);

            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", resData);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public Boolean matchList(ArrayList<String> arrylist, String str) {
        if (str == null) {
            return true;
        }
        for (String list : arrylist) {
            if (list.toLowerCase().contains(str.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public String getIPLocation(String ip) {
        InputStream database = obsDao.getData();
        try {
            DatabaseReader reader = new DatabaseReader.Builder(database).build();
            InetAddress ipAddress = InetAddress.getByName(ip);
            CityResponse response = reader.city(ipAddress);

            String continent_name = response.getContinent().getName();
            String region_iso_code = response.getMostSpecificSubdivision().getName();
            String city_name = response.getCity().getName();
            String country_iso_code = response.getCountry().getIsoCode();
            Double lon = response.getLocation().getLatitude();
            Double lat = response.getLocation().getLongitude();

            HashMap<String, Object> location = new HashMap<>();
            location.put("lon", lon);
            location.put("lat", lat);

            HashMap<String, Object> loc = new HashMap<>();
            loc.put("continent_name", continent_name);
            loc.put("region_iso_code", region_iso_code);
            loc.put("city_name", city_name);
            loc.put("country_iso_code", country_iso_code);
            loc.put("location", location);

            HashMap<String, Object> res = new HashMap<>();
            res.put("ip", ip);
            res.put("geoip", loc);

            String result = objectMapper.valueToTree(res).toString();
            return result;
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        } catch (GeoIp2Exception | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String getEcosystemRepoInfo(String community, String ecosystem_type, String sort_order) {
        String queryjson;
        String queryStr;
        String index;
        switch (community.toLowerCase()) {
            case "mindspore":
                index = mindSpore.getrepo_info_index();
                queryjson = mindSpore.getrepo_info_QuerStr();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        sort_order = sort_order == null ? "desc" : sort_order;
        try {
            queryStr = String.format(queryjson, ecosystem_type, sort_order);
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("hits").get("hits").elements();

            ArrayList<JsonNode> resList = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                JsonNode res = bucket.get("_source");
                resList.add(res);
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", resList);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }

    public String querySiglabel(String community, String sig) {
        String queryjson;
        String queryStr;
        String index;
        switch (community.toLowerCase()) {
            case "opengauss":
                index = openGauss.getSigs_index();
                queryjson = openGauss.getsig_label_queryStr();
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            queryStr = String.format(queryjson, sig);
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();
            String label = sig;
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                label = bucket.get("key").asText();
                String[] labels = label.split("/");
                label = labels[1];
            }
            return label;
        } catch (Exception e) {
            e.printStackTrace();
            return sig;
        }
    }

    public String queryUserCompany(String community, String user) {
        String queryjson;
        String queryStr;
        String index;
        String company = "independent";
        switch (community.toLowerCase()) {
            case "openeuler":
                index = openEuler.getaccount_org_index();
                queryjson = openEuler.getaccount_org_query();
                break;
            default:
                return company;
        }
        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            queryStr = String.format(queryjson, user);
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                Iterator<JsonNode> orgBuckets = bucket.get("2").get("buckets").elements();
                if (orgBuckets.hasNext()) {
                    JsonNode orgBucket = orgBuckets.next();
                    company = orgBucket.get("key").asText();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return company;
    }

    public ResponseEntity queryReviewerRecommend(PrReviewerVo input, Environment env) {
        String giteeAllIndex;
        String userTagIndex;
        try {
            String community = input.getCommunity().toLowerCase();
            switch (community) {
                case "mindspore":
                    giteeAllIndex = mindSpore.getGiteeAllIndex().replace("/", "");
                    userTagIndex = mindSpore.getUserTagIndex();
                    break;
                default:
                    return result(HttpStatus.NOT_FOUND, "the community not found", null);
            }

            List<String> robotUsers = Arrays.asList(robotUser.split(","));
            String[] userpass = Objects.requireNonNull(env.getProperty("userpass")).split(":");
            String host = env.getProperty("es.host");
            int port = Integer.parseInt(env.getProperty("es.port", "9200"));
            String scheme = env.getProperty("es.scheme");
            String esUser = userpass[0];
            String password = userpass[1];
            RestHighLevelClient restHighLevelClient = HttpClientUtils.restClient(host, port, scheme, esUser, password);
            EsQueryUtils esQueryUtils = new EsQueryUtils();

            HashMap<String, UserTagInfo> inputUser2Info = new HashMap<>();
            for (String reviewer : input.getReviewers()) {
                UserTagInfo userTagInfo = new UserTagInfo();
                userTagInfo.setGiteeId(reviewer);
                inputUser2Info.put(reviewer, userTagInfo);
            }
            // 评论过相关PR的人 + 输入的人
            HashMap<String, UserTagInfo> user2Info = esQueryUtils.QueryPrReviewerByInter(restHighLevelClient, input, giteeAllIndex, robotUsers);
            inputUser2Info.putAll(user2Info);
            // 获取评论过该仓库的人  TODO
            Map<String, Map<String, Object>> mindspore_user_tag = esQueryUtils.QueryPrReviewerByRepo(restHighLevelClient, input, userTagIndex, inputUser2Info);

            // TODO return test
            ArrayList<String> strings = new ArrayList<>(mindspore_user_tag.keySet());
            ArrayList<String> reviewers = new ArrayList<>(new HashSet<>(input.getReviewers()));
            strings.removeAll(reviewers);

            List<String> res1 = randomItems(reviewers);
            List<String> res2 = randomItems(strings);
            res2.addAll(res1);
            return result(HttpStatus.OK, "success", res2);
        } catch (Exception ex) {
            return result(HttpStatus.NOT_FOUND, "query reviewers error", null);
        }
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        return new ResponseEntity<>(res, status);
    }

    private List<String> randomItems(List<String> items) {
        Random random = new Random();
        ArrayList<String> res = new ArrayList<>();
        if (items.size() >= 2) {
            int i = random.nextInt(items.size());
            res.add(items.get(i));
            items.remove(i);
            i = random.nextInt(items.size());
            res.add(items.get(i));
        } else {
            res.addAll(items);
        }
        return res;

    }
}
