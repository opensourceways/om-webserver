package com.om.Dao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

/**
 * @author zhxia
 * @date 2020/11/16 14:37
 */
@Repository
public class RedisDao {
    @Autowired
    protected StringRedisTemplate redisTemplate;

    /**
     * 功能描述: <br>
     * 〈设置key的有效期〉
     *
     * @param key:    key
     * @param value:  value
     * @param expire: 过期时间
     * @return: boolean
     * @Author: xiazhonghai
     * @Date: 2020/11/16 16:00
     */
    public boolean set(final String key, String value, Long expire) {
        boolean result = false;
        try {
            ValueOperations operations = redisTemplate.opsForValue();
            operations.set(key, value);
            redisTemplate.expire(key, expire, TimeUnit.SECONDS);
            result = true;
        } catch (Exception e) {
            System.out.println(e);
        }
        return result;
    }

    /**
     * 功能描述: <br>
     * 〈获取key对应的value〉
     *
     * @param key: key
     * @return: java.lang.Object
     * @Author: xiazhonghai
     * @Date: 2020/11/16 16:06
     */
    public Object get(final String key) {
        Object result = null;
        try {
            ValueOperations operations = redisTemplate.opsForValue();
            result = operations.get(key);
        } catch (Exception e) {
            System.out.println(e);
        }
        return result;
    }

    /**
     * 功能描述: <br>
     * 〈判断key是否存在〉
     *
     * @param key:
     * @return: boolean
     * @Author: xiazhonghai
     * @Date: 2020/11/16 16:05
     */
    public boolean exists(final String key) {
        boolean result = false;
        try {
            result = redisTemplate.hasKey(key);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return result;
    }

    /**
     * 功能描述: <br>
     * 〈移除对应的key-value〉
     *
     * @param key: key
     * @return: boolean
     * @Author: xiazhonghai
     * @Date: 2020/11/16 16:08
     */
    public boolean remove(final String key) {
        boolean result = false;
        try {
            if (exists(key)) {
                redisTemplate.delete(key);
            }
            result = true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return result;
    }

}
