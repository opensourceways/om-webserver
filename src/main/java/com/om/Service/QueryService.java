package com.om.Service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import com.om.Utils.StringDesensitizationUtils;
import com.om.Vo.BlueZoneContributeVo;
import com.om.Vo.BlueZoneUserVo;
import com.om.Vo.IsoBuildTimesVo;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Objects;
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
        String key = community + "all";
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
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
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
        String result;
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
        result = (String) redisDao.get(key);
        if (result == null) {
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryObsDetails(community, item, branch, limit);
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

    public String queryIsoBuildTimes(IsoBuildTimesVo body, String item) {
        String key = body.getCommunity() + item + body.getLimit();
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

}

