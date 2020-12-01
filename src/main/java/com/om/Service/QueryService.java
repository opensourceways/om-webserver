package com.om.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
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
    static ObjectMapper objectMapper=new ObjectMapper();

    @Autowired
    RedisDao redisDao;

    

    @Autowired
    private Environment env;

    public String queryContributors(String community) {
        String key=community + "contributors";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryContributors(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");

            }
        }
        return result;
    }


    public String querySigs(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key=community + "sigs";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querySigs(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }

    public String queryUsers( String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key=community + "users";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryUsers(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }



    public String queryNoticeusers( String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key=community + "noticeusers";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryNoticeusers(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }


    public String queryModulenums(String community) throws InterruptedException, ExecutionException , JsonProcessingException {
        String key=community + "modulenums";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryModulenums(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }

    public String queryBusinessOsv(String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key=community + "businessosv";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryBusinessOsv(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }

    public String querycommunitymembers(String community)  {
        String key=community + "communitymembers";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.querycommunitymembers(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }
    public String queryAll( String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String key=community + "all";
        String result;
        result = (String) redisDao.get(key);
        if(result==null){
            //查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryAll(community);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            boolean set = redisDao.set(key, result, Long.valueOf(env.getProperty("spring.redis.keyexpire")));
            if(set){
                System.out.println("update "+key+" success!");
            }
        }
        return result;
    }


}

