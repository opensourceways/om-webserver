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

package com.om.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
// import com.om.Modules.DatastatRequestBody;
import com.om.Utils.PageUtils;
import com.om.Utils.RSAUtil;
import com.om.Utils.StringDesensitizationUtils;
import com.om.Utils.StringValidationUtil;
import com.om.Vo.*;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutionException;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;


/**
 * @author zhxia
 * @date 2020/10/22 11:40
 */
@Service
public class QueryService {
    @Autowired
    QueryDao queryDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    private Environment env;

    @Autowired
    private ErrorAlertService errorAlertService;

    @Autowired
    AuthingUserDao authingUserDao;

    public String queryContributors(String community) {
        String key = community + "contributors";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryContributors(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");

            }
        }
        return result;
    }

    public String queryDurationAggFromProjectHostarchPackage(String community) {
        String key = community + "avgDuration";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryDurationAggFromProjectHostarchPackage(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigs(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "sigs";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigs(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryUsers(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "users";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryUsers(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryNoticeusers(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "noticeusers";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryNoticeusers(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryModulenums(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "modulenums";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryModulenums(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryBusinessOsv(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "businessosv";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryBusinessOsv(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querycommunitymembers(String community) {
        String key = community + "communitymembers";
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querycommunitymembers(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryAll(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community.toLowerCase() + "all";
        String result;
        JsonNode old_data = null;
        JsonNode new_data = null;
        result = (String) redisDao.get(key);
        System.out.println("(String) redisDao.get(key) = " + key);
        System.out.println(result);

        Boolean is_flush = false;
        ObjectMapper objectMapper = new ObjectMapper();

        if (result != null) {
            JsonNode all = objectMapper.readTree(result);
            String update_at = all.get("update_at").asText();
            old_data = all.get("data");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
            try {
                Date update_date = sdf.parse(update_at);
                Date now = new Date();
                long diffs = (now.getTime() - update_date.getTime());
                if (diffs >  Long.valueOf(env.getProperty("redis.flush.interval"))) {
                    is_flush = true;
                }
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }

        if (is_flush || result == null) {
            // 查询数据库，更新redis 缓存。
            Boolean flag = false;
            try {
                String result_new = queryDao.queryAll(community);
                System.out.println("queryDao.queryAll(community) ");
                System.out.println("result_new = " + result_new);
                JsonNode all_new = objectMapper.readTree(result_new);
                new_data = all_new.get("data");
                if (old_data != null) {
                    flag = errorAlertService.errorAlert(community, old_data, new_data);
                }
                if (!flag) {
                    boolean set = redisDao.set(key, result_new, -1l);
                    System.out.println("set result_new = " + result_new);
                    if (set) {
                        System.out.println("update " + key + " success!");
                    }
                    result = result_new;
                }
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    public String queryCount(String community, String item) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + item;
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCount(community, item);
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryDownload(String community, String item) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + item;
        String result = "";
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryDownload(community, item);
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryBlueZoneContributes(BlueZoneContributeVo body, String item) throws InterruptedException, ExecutionException, JsonProcessingException {
        String token = env.getProperty("blueZone.api.token");
        if (StringUtils.isBlank(body.getToken()) || !body.getToken().equals(token)) {
            return "{\"code\":401,\"data\":{\"" + item + "\":\"token error\"},\"msg\":\"token error\"}";
        }
        String result = "{\"code\":500,\"data\":{\"" + item + "\":\"bad request\"},\"msg\":\"bad request\"}";
        //查询数据库，更新redis 缓存。
        try {
            result = queryDao.queryBlueZoneContributes(body, item);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }

        return result;
    }

    public String putBlueZoneUser(BlueZoneUserVo userVo, String item) throws InterruptedException, ExecutionException, JsonProcessingException {
        String token = env.getProperty("blueZone.api.token");
        if (StringUtils.isBlank(userVo.getToken()) || !userVo.getToken().equals(token)) {
            return "{\"code\":401,\"data\":{\"" + item + "\":\"token error\"},\"msg\":\"token error\"}";
        }
        String result = "{\"code\":500,\"data\":{\"" + item + "\":\"bad request\"},\"msg\":\"bad request\"}";
        //查询数据库，更新redis 缓存。
        try {
            result = queryDao.putBlueZoneUser(userVo, item, env);
        } catch (SocketTimeoutException ex) {
            ex.printStackTrace();
            return "{\"code\":504,\"data\":{\"" + item + "\":\"Socket Timeout\"},\"msg\":\"60 seconds timeout on connection\"}";
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

    public String queryOrgStarAndFork(String community, String item) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + item;
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryOrgStarAndFork(community, item);
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCveDetails(String community, String item, String lastCursor, String pageSize) {
        String key = community + item;
        String result;
        if (pageSize != null) {
            result = null;
        } else {
            result = (String) redisDao.get(key);
        }
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCveDetails(community, item, lastCursor, pageSize, env);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set;
            if (pageSize != null) {
                set = false;
            } else {
                set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            }
//            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querylts2203(String community, String user, String item) {
        String key = community + item;
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querylts2203(community, user, item, env);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = false; //redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryNewYear(String community, String user, String year) {
        String key = community + user + year;
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryNewYear(community, user, year);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = false;//redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryNewYearMonthCount(String community, String user) {
        String key = community + user + "monthcount";
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryNewYearMonthCount(community, user);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = false; //redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    } 

    public String queryBugQuestionnaire(String community, String item, String lastCursor, String pageSize) {

        String key = community + item;
        String result = null;

        if (pageSize == null) {
            result = (String) redisDao.get(key);
        }

        if (result != null) {
            return result;
        } else {
            result = queryDao.queryBugQuestionnaire(community, item, lastCursor, pageSize, env);
            result = dataDesensitizationProcessing(result, item);
        }

        boolean set;
        if (pageSize != null) {
            set = false;
        } else {
            set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
        }

        if (set) {
            System.out.println("update " + key + " success!");
        }

        return result;
    }

    private String dataDesensitizationProcessing(String jsonRes, String item) {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode dataMap;
        try {
            dataMap = objectMapper.readTree(jsonRes);
            Iterator<JsonNode> buckets = dataMap.get("data").elements();
            ArrayList<JsonNode> dataList = new ArrayList<>();
            while (buckets.hasNext()) {
                ObjectNode bucket = (ObjectNode) buckets.next();
                String email = bucket.get("email").asText();
                String desensitizedEmail = StringDesensitizationUtils.maskEmail(email);
                bucket.put("email", desensitizedEmail);
                dataList.add(bucket);
            }
            ObjectNode resMap = (ObjectNode) dataMap;
            resMap.putPOJO("data", dataList);
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":\"query error\"}";
        }
    }

    public String queryObsDetails(String community, String item, String branch, String limit) {
        String key = community + item + branch + limit;
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryObsDetails(community, item, branch, limit);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = true; //redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryIsoBuildTimes(IsoBuildTimesVo body, String item) {
        String key = body.getCommunity() + item;
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryIsoBuildTimes(body, item);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = true; //redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigDetails(SigDetailsVo body, String item) {
        String key = body.getCommunity() + item;
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigDetails(body, item);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = true; //redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanyContributors(String community, String item, String contributeType, String timeRange, String repo) {
        String key = community.toLowerCase() + item + contributeType.toLowerCase() + timeRange.toLowerCase() + repo ;
        String result;
        String sig = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanyContributors(community, item, contributeType, timeRange, repo, sig);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryUserContributors(String community, String item, String contributeType, String timeRange, String repo) {
        String key = community.toLowerCase() + item + contributeType.toLowerCase() + timeRange.toLowerCase() + repo;
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryUserContributors(community, item, contributeType, timeRange, repo);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryIssueScore(String community, String start_date, String end_date, String item) {

        String result = null;
        try {
            result = queryDao.queryIssueScore(community, start_date, end_date, item);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

    public String queryBuildCheckInfo(BuildCheckInfoQueryVo queryBody, String item, String lastCursor, String pageSize) {
        String validateResult = validateBuildCheckInfo(queryBody, item);
        if (!StringUtils.isBlank(validateResult)) {
            return validateResult;
        }
        String res = queryDao.queryBuildCheckInfo(queryBody, item, env, lastCursor, pageSize);

        return res;
    }

    private String validateBuildCheckInfo(BuildCheckInfoQueryVo buildCheckInfoQueryVo, String item) {
        List<String> communityNameList = Arrays.asList("openeuler", "opengauss", "openlookeng", "mindspore");
        List<String> checkTotalValidField = Arrays.asList("success", "failed");
        double MIN_BUILD_DURATION = 0;
        double min_duration_time = MIN_BUILD_DURATION;
        String errorMsg = "";


        String community_name = buildCheckInfoQueryVo.getCommunity_name();
        if (!communityNameList.contains(community_name.toLowerCase())) {
            errorMsg = "community name is invalid, Only allows: openeuler,opengauss, openlookeng, mindspore";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }

        String check_total = buildCheckInfoQueryVo.getCheck_total();
        if (!StringUtils.isBlank(check_total) && !checkTotalValidField.contains(check_total.toLowerCase())) {
            errorMsg = "check_total is invalid, Only allows: SUCCESS and FAILED";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }

        Map<String, String> build_duration = buildCheckInfoQueryVo.getBuild_duration();
        if (StringUtils.isNotBlank(build_duration.get("min_duration_time"))) {
            min_duration_time = Double.parseDouble(build_duration.get("min_duration_time"));
            if (min_duration_time < MIN_BUILD_DURATION) {
                errorMsg = "build_time is invalid, Only allows: bigger than " + MIN_BUILD_DURATION + "";
                return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
            }
        }


        Map<String, String> pr_create_time = buildCheckInfoQueryVo.getPr_create_time();
        Map<String, String> result_build_time = buildCheckInfoQueryVo.getResult_build_time();
        Map<String, String> result_update_time = buildCheckInfoQueryVo.getResult_update_time();
        Map<String, String> mistake_update_time = buildCheckInfoQueryVo.getMistake_update_time();

        String pr_create_start_time = pr_create_time.get("start_time");
        String pr_create_end_time = pr_create_time.get("end_time");
        String result_build_start_time = result_build_time.get("start_time");
        String result_build_end_time = result_build_time.get("end_time");
        String result_update_start_time = result_update_time.get("start_time");
        String result_update_end_time = result_update_time.get("end_time");
        String mistake_update_start_time = mistake_update_time.get("start_time");
        String mistake_update_end_time = mistake_update_time.get("end_time");

        if (!StringValidationUtil.isDateTimeStrValid(pr_create_start_time)) {
            errorMsg = "pr_create_start_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(pr_create_end_time)) {
            errorMsg = "pr_create_end_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(result_build_start_time)) {
            errorMsg = "result_build_start_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(result_build_end_time)) {
            errorMsg = "result_build_end_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(result_update_start_time)) {
            errorMsg = "result_update_start_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(result_update_end_time)) {
            errorMsg = "result_update_end_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(mistake_update_start_time)) {
            errorMsg = "mistake_update_start_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }
        if (!StringValidationUtil.isDateTimeStrValid(mistake_update_end_time)) {
            errorMsg = "mistake_update_end_time format is invalid";
            return "{\"code\":400,\"data\":{\"" + item + "\":\"query error\"},\"msg\":" + errorMsg + "}";
        }

        return null;
    }

    public String putUserActionsinfo(String community, String data) throws InterruptedException, ExecutionException, JsonProcessingException {
        String result = "{\"code\":500, \"data\":\"bad request\",\"msg\":\"bad request\"}";
        try {
            result = queryDao.putUserActionsinfo(community, data, env);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public String querySigName(String community, String lang) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "sigsname" + lang;
        String result;        
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            result = queryDao.querySigName(community, lang);           
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigInfo(String community, String sig, String repo, String user, String search, String page, String pageSize) 
            throws JsonMappingException, JsonProcessingException {
        if (search != null && search.equals("fuzzy")){
            return queryFuzzySigInfo(community, sig, repo, user, search, page, pageSize);
        }
        return querySigInfo(community, sig);
    }

    public String querySigInfo(String community, String sig) throws JsonMappingException, JsonProcessingException {
        String key = community + sig + "siginfo";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            result = queryDao.querySigInfo(community, sig);
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryFuzzySigInfo(String community, String sig, String repo, String user, String search, String page, String pageSize) 
            throws JsonMappingException, JsonProcessingException {
        String key = community + "allsiginfo";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            result = queryDao.querySigInfo(community, null);
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode all = objectMapper.readTree(result);
        if (all.get("code").asInt() != 200){
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        JsonNode res = all.get("data");
        ArrayList<HashMap<String, Object>> resList = objectMapper.convertValue(res,
                new TypeReference<ArrayList<HashMap<String, Object>>>() {});      
        ArrayList<HashMap<String, Object>> tempList = new ArrayList<>();
        for (HashMap<String, Object> list : resList){
            String sig_name = list.get("sig_name").toString();
            ArrayList<String> repos = (ArrayList<String>) list.get("repos");
            Boolean bool = sig != null && !sig_name.toLowerCase().contains(sig.toLowerCase()) ? false : true;
            ArrayList<String> maintainers = (ArrayList<String>) list.get("maintainers");
            if (bool && queryDao.matchList(repos, repo) && queryDao.matchList(maintainers, user)){
                tempList.add(list);
            }
        }

        Collections.sort(tempList, new Comparator<HashMap<String, Object>>() {
            @Override
            public int compare(HashMap<String, Object> t1, HashMap<String, Object> t2) {
                return t1.get("sig_name").toString().toLowerCase()
                        .compareTo(t2.get("sig_name").toString().toLowerCase());
            }
        });

        if (pageSize != null && page != null) {
            int currentPage = Integer.parseInt(page);
            int pagesize = Integer.parseInt(pageSize);
            Map data = PageUtils.getDataByPage(currentPage, pagesize, tempList);
            ArrayList<HashMap<String, Object>> dataList = new ArrayList<>();
            dataList.add((HashMap<String, Object>) data);
            tempList = dataList;
        }
        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", 200);
        resMap.put("data", tempList);
        resMap.put("msg", "success");
        result = objectMapper.valueToTree(resMap).toString();
        return result;
    }

    public String querySigRepo(String community, String sig, String page, String pageSize)
            throws JsonMappingException, JsonProcessingException {
        String key = community.toLowerCase() + sig + "repo";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigRepo(community, sig);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        if (pageSize != null && page != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode all = objectMapper.readTree(result);
            if (all.get("data") != null) {
                JsonNode res = all.get("data");
                ArrayList<String> resList = objectMapper.convertValue(res,
                        new TypeReference<ArrayList<String>>() {
                        });

                int currentPage = Integer.parseInt(page);
                int pagesize = Integer.parseInt(pageSize);
                Map data = PageUtils.getDataByPage(currentPage, pagesize, resList);
                ArrayList<HashMap<String, Object>> dataList = new ArrayList<>();
                dataList.add((HashMap<String, Object>) data);
                HashMap<String, Object> resMap = new HashMap<>();
                resMap.put("code", 200);
                resMap.put("data", dataList);
                resMap.put("msg", "success");
                result = objectMapper.valueToTree(dataList).toString();
            }
        }
        return result;
    }

    public String querySigCompanyContributors(String community, String item, String contributeType, String timeRange, String sig) {
        String key = community.toLowerCase() + item + contributeType.toLowerCase() + timeRange.toLowerCase() + sig ;
        String result;
        String repo = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanyContributors(community, item, contributeType, timeRange, repo, sig);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanyName(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community.toLowerCase() + "companyname";
        String result;       
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanyName(community);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanyUsercontribute(String community, String company, String contributeType,
            String timeRange, String token) {
        Boolean per = getPermission(token, community, company);
        if (!per) {
            return "{\"code\":400,\"msg\":\"No Permission!\"}";
        }
        String key = community.toLowerCase() + company + "usertypecontribute_" + contributeType.toLowerCase()
                + timeRange.toLowerCase();
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryGroupUserContributors(community, "company", company, contributeType, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanySigcontribute(String community, String company, String contributeType,
            String timeRange, String token) {
        Boolean per = getPermission(token, community, company);
        if (!per) {
            return "{\"code\":400,\"msg\":\"No Permission!\"}";
        }
        String key = community.toLowerCase() + company + "sigtypecontribute_" + contributeType.toLowerCase() + timeRange.toLowerCase();
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryGroupSigcontribute(community, company, "company", contributeType, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanySigDetails(String community, String company, String timeRange, String token) {
        Boolean per = getPermission(token, community, company);
        if (!per) {
            return "{\"code\":400,\"msg\":\"No Permission!\"}";
        }
        String key = community.toLowerCase() + company + "sig" + timeRange.toLowerCase();
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanySigDetails(community, company, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigUserTypeCount(String community, String sig, String contributeType, String timeRange) {
        String key = community.toLowerCase() + sig + "usertypecontribute_" + contributeType.toLowerCase()  + timeRange.toLowerCase();
        String result = null;      
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryGroupUserContributors(community, "sig", sig, contributeType, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanyUsers(String community, String company, String timeRange, String token) {
        Boolean per = getPermission(token, community, company);
        if (!per) {
            return "{\"code\":400,\"msg\":\"No Permission!\"}";
        }
        String key = community.toLowerCase() + company + "companyusers" + timeRange.toLowerCase();
        String result = null;      
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanyUsers(community, company, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCommunityRepos(String community) {
        String key = community.toLowerCase() + "repos";
        String result = null;
        result = null; // (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCommunityRepos(community);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigScore(String community, String sig, String timeRange) {
        String key = community.toLowerCase() + sig + "sigscore" + timeRange.toLowerCase();
        String result = null;
        String type = "";      
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigScore(community, sig, timeRange, type);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigScoreAll(String community) {
        Date now = new Date();
        SimpleDateFormat simple = new SimpleDateFormat("yyyyMMdd");
        String keyStr = simple.format(now);
        String key = community.toLowerCase() + "sigscoreall" + keyStr;
        String result = null;   
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigScoreAll(community);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigRadarScore(String community, String sig, String timeRange) {
        String key = community.toLowerCase() + sig + "sigradarscore" + timeRange.toLowerCase();
        String result = null;
        String type = "radar";      
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigScore(community, sig, timeRange, type);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryCompanySigs(String community, String timeRange) {
        String key = community.toLowerCase() + "companysigs" + timeRange.toLowerCase();
        String result = null;    
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanySigs(community, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigsOfTCOwners(String community) {
        String key = community.toLowerCase() + "sigs_of_tc_owners";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigsOfTCOwners(community);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
            System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryUserSigcontribute(String community, String user, String contributeType,
            String timeRange) {
        String key = community.toLowerCase() + user + "sigtypecontribute_" + contributeType.toLowerCase() + timeRange.toLowerCase();
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryGroupSigcontribute(community, user, "user", contributeType, timeRange);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryUserOwnertype(String community, String user, String username)
            throws JsonProcessingException {
        String key = community.toLowerCase() + "all" + "ownertype";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryAllUserOwnertype(community);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }

        String giteeLogin = StringUtils.isNotBlank(user) ? user.toLowerCase() : getGiteeLoginFromAuthing(username);

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode all = objectMapper.readTree(result);
        JsonNode userData = all.get("data").get(giteeLogin);
        if (userData != null) {
            result = objectMapper.valueToTree(userData).toString();
        } else {
            result = "[]";
        }
        result = "{\"code\":200,\"data\":" + result + ",\"msg\":\"ok\"}";
        return result;
    }

    private String getGiteeLoginFromAuthing(String username) {
        String giteeLogin = "";
        if (StringUtils.isBlank(username)) {
            return giteeLogin;
        }
        try {
            JSONObject userInfo = authingUserDao.getUserByName(username);
            JSONArray identities = userInfo.getJSONArray("identities");
            for (Object identity : identities) {
                JSONObject identityObj = (JSONObject) identity;
                String originConnId = identityObj.getJSONArray("originConnIds").get(0).toString();
                if (!originConnId.equals(env.getProperty("enterprise.connId.gitee"))) continue;
                giteeLogin = identityObj.getJSONObject("userInfoInIdp").getJSONObject("customData")
                        .getString("giteeLogin");
            }
        } catch (Exception ignored) {
        }
        return giteeLogin;
    }

    public String queryUserContributeDetails(String community, String user, String sig, String contributeType,
            String timeRange, String page, String pageSize, String comment_type, String filter) throws JsonMappingException, JsonProcessingException {
        String key = community.toLowerCase() + sig + contributeType.toLowerCase() + timeRange.toLowerCase() + comment_type;
        String result = null;
        result = (String) redisDao.get(key, user);
        // if (filter == null){
        //     result = (String) redisDao.get(key, user);
        // } else {
        //     result = queryDao.queryUserContributeDetails(community, user, sig, contributeType, timeRange, env, comment_type, filter);
        // }

        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryUserContributeDetails(community, user, sig, contributeType, timeRange, env, comment_type, filter);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, user, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " " + user + " hash success!");
            }
        }
        if (page != null && pageSize != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode all = objectMapper.readTree(result);
            if (all.get("data").get(user) == null) {
                return result;
            }
            Iterator<JsonNode> buckets = all.get("data").get(user).iterator();
            ArrayList<JsonNode> usercount = new ArrayList<>();
            ArrayList<JsonNode> filterRes = new ArrayList<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                if (filter == null) {
                    usercount.add(bucket);
                }               
                if (filter != null && bucket.get("info").toString().contains(filter)) {
                    filterRes.add(bucket);
                }
            }
            ArrayList<JsonNode> resList = filter == null ? usercount : filterRes;
            Map map = PageUtils.getDataByPage(Integer.parseInt(page), Integer.parseInt(pageSize), resList);
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", map);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        }
        return result;
    }

    public String queryUserLists(String community, String group, String name) {
        String key = community.toLowerCase() + group + name + "userlist";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryUserLists(community, group, name);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigRepoCommitters(String community, String sig) {
        String key = community.toLowerCase() + sig + "committers";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigRepoCommitters(community, sig);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String getIPLocation(String ip) {
        String result = null;
        // 查询数据库，更新redis 缓存。
        try {
            result = queryDao.getIPLocation(ip);
        } catch (Exception e) {
            e.printStackTrace();
        }  
        return result;
    }

    public String getEcosystemRepoInfo(String community, String ecosystem_type, String lang, String sort_type,
            String sort_order, String page, String pageSize) throws JsonMappingException, JsonProcessingException {
        lang = lang == null ? "zh" : lang.toLowerCase();
        String key = community.toLowerCase() + ecosystem_type.toLowerCase() + "ecosysteminfo" + sort_order + lang;
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.getEcosystemRepoInfo(community, ecosystem_type, lang, sort_order);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.keyexpire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode all = objectMapper.readTree(result);
        if (all.get("code").asInt() != 200) {
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
        JsonNode res = all.get("data");
        ArrayList<HashMap<String, Object>> resList = objectMapper.convertValue(res,
                new TypeReference<ArrayList<HashMap<String, Object>>>() {
                });

        if (sort_type != null && (sort_type.equals("date") || sort_type.equals("repo"))) {
            resList = sortbytype(resList, sort_type, sort_order);
        }

        if (pageSize != null && page != null && resList.size() > 0) {
            String type = resList.get(0).get("type").toString();
            String name = resList.get(0).get("name").toString();
            String description = resList.get(0).get("description").toString();
            int currentPage = Integer.parseInt(page);
            int pagesize = Integer.parseInt(pageSize);
            Map data = PageUtils.getDataByPage(currentPage, pagesize, resList);
            data.put("type", type);
            data.put("name", name);
            data.put("description", description);
            ArrayList<HashMap<String, Object>> dataList = new ArrayList<>();
            dataList.add((HashMap<String, Object>) data);
            resList = dataList;
        }
        HashMap<String, Object> resMap = new HashMap<>();
        resMap.put("code", 200);
        resMap.put("data", resList);
        resMap.put("msg", "success");
        result = objectMapper.valueToTree(resMap).toString();
        return result;
    }

    public ArrayList<HashMap<String, Object>> sortbytype(ArrayList<HashMap<String, Object>> dataList, String type, String order) {
        switch (order.toLowerCase()) {
            case "asc":
                Collections.sort(dataList, new Comparator<HashMap<String, Object>>() {
                    @Override
                    public int compare(HashMap<String, Object> t1, HashMap<String, Object> t2) {
                        return t1.get(type).toString().toLowerCase()
                                .compareTo(t2.get(type).toString().toLowerCase());
                    }
                });
                return dataList;
            case "desc":
                Collections.sort(dataList, new Comparator<HashMap<String, Object>>() {
                    @Override
                    public int compare(HashMap<String, Object> t1, HashMap<String, Object> t2) {
                        return t2.get(type).toString().toLowerCase()
                                .compareTo(t1.get(type).toString().toLowerCase());
                    }
                });
                return dataList;
            default:
                return null;
        }
        
    }

    private Boolean getPermission(String token, String community, String company) {
        if (null == token) {
            return false;
        }
        try {
            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(env.getProperty("rsa.authing.privateKey"));
            DecodedJWT decode = JWT.decode(RSAUtil.privateDecrypt(token, privateKey));
            String userId = decode.getAudience().get(0);
            String permissionList = decode.getClaim("permissionList").asString();
            String[] pers = new String(Base64.getDecoder().decode(permissionList.getBytes())).split(",");
            for (String per : pers) {
                String[] perList = per.split(":");
                if (perList.length > 1 && perList[1].equalsIgnoreCase(env.getProperty("openeuler.companyAction"))){
                    return true;
                }                   
            }
            
            org.json.JSONObject userObj = authingUserDao.getUserById(userId);
            HashMap<String, Map<String, Object>> map = new HashMap<>();
            org.json.JSONArray jsonArray = userObj.getJSONArray("identities");
            for (Object o : jsonArray) {
                org.json.JSONObject obj = (org.json.JSONObject) o;
                authingUserIdentityIdp(obj, map);
            }
            if (null != map.get("oauth2") && null != map.get("oauth2").get("login_name")) {
                String login = map.get("oauth2").get("login_name").toString();
                String org = queryDao.queryUserCompany(community, login);
                ArrayList<String> companyNameList = queryDao.getcompanyNameList(company);
                for (String name: companyNameList){
                    if (org.equals(name))
                    return false;//true;
                }               
            }
        } catch (Exception ex) {
            System.out.println("Identities Get Error");
        }
        return false;
    }

    private void authingUserIdentityIdp(org.json.JSONObject identityObj, HashMap<String, Map<String, Object>> map) {
        HashMap<String, Object> res = new HashMap<>();
        org.json.JSONObject userInfoInIdpObj = identityObj.getJSONObject("userInfoInIdp");
        String provider = jsonObjStringValue(identityObj, "provider");
        switch (provider) {
            case "oauth2":
                String gitee_login = userInfoInIdpObj.getJSONObject("customData").getString("giteeLogin");
                res.put("login_name", gitee_login);
                map.put(provider, res);
                break;
            default:
                break;
        }
    }

    private String jsonObjStringValue(org.json.JSONObject jsonObj, String nodeName) {
        String res = "";
        try {
            if (jsonObj.isNull(nodeName))
                return res;
            Object obj = jsonObj.get(nodeName);
            if (obj != null)
                res = obj.toString();
        } catch (Exception ex) {
            System.out.println(nodeName + "Get Error");
        }
        return res;
    }

    public ResponseEntity queryReviewerRecommend(PrReviewerVo input) {
        String key =  "reviewer_recommend_" + input.getCommunity(); //community.toLowerCase() + contributeType + "committers";
        ResponseEntity result = null;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryReviewerRecommend(input, env);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = true; //redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String getSigReadme(String community, String sig, String lang) {
        String key = community.toLowerCase() + sig + "readme" + lang;
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.getMindsporeSigReadme(community, sig, lang);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String queryAuthingUserInfo(String userid) {
        org.json.JSONObject userObj = authingUserDao.getUserById(userid);
        HashMap<String, Object> resmap = new HashMap<>();
        HashMap<String, Map<String, Object>> map = new HashMap<>();
        org.json.JSONArray jsonArray = userObj.getJSONArray("identities");

        String email = userObj.get("email") != null ? userObj.get("email").toString() : "";
        String nickname = userObj.get("nickname") != null ? userObj.get("nickname").toString() : "";
        String username = userObj.get("username") != null ? userObj.get("username").toString() : "";
        resmap.put("username", username);
        resmap.put("email", email);
        resmap.put("nickname", nickname);
        for (Object o : jsonArray) {
            org.json.JSONObject obj = (org.json.JSONObject) o;
            authingUserIdentityIdp(obj, map);
        }
        if (null != map.get("oauth2") && null != map.get("oauth2").get("login_name")) {
            String login = map.get("oauth2").get("login_name").toString();
            resmap.put("gitee_id", login);
        }
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.valueToTree(resmap).toString();
    }
}

