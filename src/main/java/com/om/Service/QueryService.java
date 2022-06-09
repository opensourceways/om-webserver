package com.om.Service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Utils.StringDesensitizationUtils;
import com.om.Utils.StringValidationUtil;
import com.om.Vo.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutionException;

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
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryAll(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.key.expire")));
            if (set) {
                System.out.println("update " + key + " success!");
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

    public String queryNewYear(String community, String user, String item) {
        String key = community + item;
        String result;
        result = null; //(String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryNewYear(community, user, item, env);
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
            result = dataDesensitizationProcessing(result);
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

    private String dataDesensitizationProcessing(String jsonRes) {
        LinkedHashMap<String, Object> jsonMap = JSON.parseObject(jsonRes, LinkedHashMap.class, Feature.OrderedField);
        JSONObject dataMap = new JSONObject(jsonMap);
        JSONArray dataList = (JSONArray) dataMap.get("data");

        for (int i = 0; i < dataList.size(); i++) {
            JSONObject eachQuestionnaire = dataList.getJSONObject(i);
            String email = (String) eachQuestionnaire.get("email");
            String desensitizedEmail = StringDesensitizationUtils.maskEmail(email);
            eachQuestionnaire.put("email", desensitizedEmail);
        }
        dataMap.put("data", dataList);

        return dataMap.toJSONString();
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

    public String queryCompanyContributors(String community, String item, String contributeType, String timeRange, String repo, String sig) {
        String key = community.toLowerCase() + item + contributeType.toLowerCase() + timeRange.toLowerCase() + repo + sig;
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryCompanyContributors(community, item, contributeType, timeRange, repo, sig);
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
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
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

    public String queryBuildCheckInfo(BuildCheckInfoQueryVo queryBody, String item) {
        String validateResult = validateBuildCheckInfo(queryBody, item);
        if (!StringUtils.isBlank(validateResult)) {
            return validateResult;
        }
        String res = queryDao.queryBuildCheckInfo(queryBody, item, env);

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
        String result = "{\"code\":500, \"bad request\"},\"msg\":\"bad request\"}";
        try {
            result = queryDao.putUserActionsinfo(community, data, env);
        } catch (SocketTimeoutException ex) {
            ex.printStackTrace();
            return "{\"code\":504, \"Socket Timeout\"},\"msg\":\"60 seconds timeout on connection\"}";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public String querySigName(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key = community + "sigsname";
        String result;        
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            result = queryDao.querySigName(community);           
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigRepo(String community, String sig, String timeRange) {
        String key = community.toLowerCase() + sig + "repo" + timeRange.toLowerCase();
        String result;
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigRepo(community, sig, timeRange);
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
    
    public String querySigDetails(String community, String sig, String timeRange, String curDate) {
        String key = community.toLowerCase() + sig + "details" + timeRange.toLowerCase();
        String result;   

        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigDetails(community, sig, timeRange, curDate);
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
            String timeRange) {
        String key = community.toLowerCase() + company + "usertypecontribute" + timeRange.toLowerCase();
        String result = "";
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryGroupUserContributors(community, "company", company, contributeType, timeRange);
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

    public String queryCompanySigDetails(String community, String company, String timeRange) {
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
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }
        return result;
    }

    public String querySigUserTypeCount(String community, String sig, String contributeType, String timeRange) {
        String key = community.toLowerCase() + sig + "usertypecontribute" + timeRange.toLowerCase();
        String result;      
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryGroupUserContributors(community, "sig", sig, contributeType, timeRange);
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

    public String queryCompanyUsers(String community, String company, String timeRange) {
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
            boolean set = redisDao.set(key, result, Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
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

}

