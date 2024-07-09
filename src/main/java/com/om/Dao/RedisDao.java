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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.om.Modules.MessageCodeConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.stereotype.Repository;


/**
 * Redis 数据访问对象类.
 */
@Repository
public class RedisDao {
    /**
     * RedisTemplate 字符串类型.
     */
    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * ObjectMapper 实例，用于JSON序列化和反序列化.
     */
    private static ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 日志记录器，用于记录 RedisDao 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RedisDao.class);

    /**
     * 获取登录错误计数.
     *
     * @param loginErrorKey 登录错误键
     * @return 登录错误计数
     */
    public int getLoginErrorCount(String loginErrorKey) {
        Object loginErrorCount = this.get(loginErrorKey);
        return loginErrorCount == null ? 0 : Integer.parseInt(loginErrorCount.toString());
    }

    /**
     * 获取过期时间.
     * 没有设置过期时间，返回-1
     * 没有找到该key，返回-2
     *
     * @param key key
     * @return 还剩多少秒过期
     */
    public long expire(String key) {
        Long keyExpire = redisTemplate.opsForValue().getOperations().getExpire(key);
        if (Objects.isNull(keyExpire)) {
            return -1;
        }
        return keyExpire;
    }

    /**
     * 通过设置偏移量来修改value，不会更改过期时间.
     * offset = 0 表示不偏移
     * 注意：这种情况要修改的值，长度不能比原值长度小
     *
     * @param key    key
     * @param value  value
     * @param offset 偏移量
     * @return boolean
     */
    public boolean updateValue(String key, String value, long offset) {
        boolean result = false;
        if (exists(key)) {
            redisTemplate.opsForValue().set(key, value, offset);
            result = true;
        }
        return result;
    }

    /**
     * 设置键值对，并设置过期时间.
     *
     * @param key    键
     * @param value  值
     * @param expire 过期时间
     * @return 是否成功设置的布尔值
     */
    public boolean set(final String key, String value, Long expire) {
        boolean result = false;
        try {
            if (!checkValue(value)) {
                return false;
            }
            redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
            ValueOperations operations = redisTemplate.opsForValue();
            operations.set(key, value);
            if (expire < 1) {
                redisTemplate.persist(key);
            } else {
                redisTemplate.expire(key, expire, TimeUnit.SECONDS);
            }
            result = true;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result;
    }

    /**
     * 获取key对应的value.
     *
     * @param key 键
     * @return 对应的值对象
     */
    public Object get(final String key) {
        Object result = null;
        redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
        try {
            ValueOperations operations = redisTemplate.opsForValue();
            result = operations.get(key);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result;
    }

    /**
     * list追加.
     *
     * @param key 键
     * @param value 值
     * @param expire 过期时间
     * @return 是否添加成功
     */
    public boolean addList(final String key, String value, Integer expire) {
        boolean result = false;
        try {
            redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
            redisTemplate.opsForList().leftPush(key, value);
            if (expire < 1) {
                redisTemplate.persist(key);
            } else {
                redisTemplate.expire(key, expire, TimeUnit.SECONDS);
            }
            result = true;
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return result;
    }

    /**
     * 移除末尾值.
     *
     * @param key 键
     * @param leaveNum 可保留长度
     * @return 是否成功
     */
    public boolean removeListTail(final String key, int leaveNum) {
        boolean result = false;
        if (leaveNum <= 0) {
            return result;
        }
        try {
            redisTemplate.opsForList().trim(key, 0, leaveNum - 1);
            result = true;
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return result;
    }

    /**
     * 移除指定值.
     *
     * @param key 键
     * @param value 值
     * @return 是否移除成功
     */
    public boolean removeListValue(final String key, String value) {
        boolean result = false;
        try {
            redisTemplate.opsForList().remove(key, 1, value);
            result = true;
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return result;
    }

    /**
     * 获取链表长度.
     *
     * @param key 键
     * @return 长度
     */
    public Long getListSize(final String key) {
        Long result = 0L;
        try {
            result = redisTemplate.opsForList().size(key);
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return result;
    }

    /**
     * 是否包含某个值.
     *
     * @param key 键
     * @param value 值
     * @return 是否包含
     */
    public boolean containListValue(final String key, String value) {
        boolean result = false;
        try {
            List<String> list = redisTemplate.opsForList().range(key, 0, -1);
            if (list != null && list.contains(value)) {
                result = true;
            }
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return result;
    }

    /**
     * 设置过期时间.
     *
     * @param key 键
     * @param expire 过期时间
     * @return 设置结果
     */
    public Boolean setKeyExpire(final String key, long expire) {
        Boolean result = false;
        try {
            result = redisTemplate.expire(key, expire, TimeUnit.SECONDS);
        } catch (Exception e) {
            LOGGER.error("Internal Server Error {}", e.getMessage());
        }
        return result;
    }

    /**
     * 设置哈希表中字段的值，并设置过期时间.
     *
     * @param key    哈希表键
     * @param field  字段名
     * @param value  字段值
     * @param expire 过期时间
     * @return 是否成功设置的布尔值
     */
    public boolean set(final String key, String field, String value, Long expire) {
        boolean result = false;
        try {
            if (!checkValue(value)) {
                return false;
            }
            redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
            HashOperations<String, String, String> map = redisTemplate.opsForHash();
            map.put(key, field, value);
            redisTemplate.expire(key, expire, TimeUnit.SECONDS);
            result = true;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result;
    }

    /**
     * 获取哈希表中字段的值.
     *
     * @param key   哈希表键
     * @param field 字段名
     * @return 字段值对象
     */
    public Object get(final String key, String field) {
        Object result = null;
        redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
        try {
            HashOperations<String, String, String> hashOperations = redisTemplate.opsForHash();
            result = hashOperations.get(key, field);
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result;
    }

    /**
     * 检查键是否存在.
     *
     * @param key 键
     * @return 键是否存在的布尔值
     */
    public boolean exists(final String key) {
        boolean result = false;
        try {
            Boolean isExists = redisTemplate.hasKey(key);
            if (Objects.nonNull(isExists)) {
                result = isExists;
            }
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result;
    }

    /**
     * 删除指定键及其对应的值.
     *
     * @param key 键
     * @return 删除操作是否成功的布尔值
     */
    public boolean remove(final String key) {
        boolean result = false;
        try {
            if (exists(key)) {
                redisTemplate.delete(key);
            }
            result = true;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
        }
        return result;
    }


    private RedisSerializer getJsonserializer() {
        Jackson2JsonRedisSerializer jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer(Object.class);
        ObjectMapper om = new ObjectMapper();
        om.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        om.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        jackson2JsonRedisSerializer.setObjectMapper(om);
        return jackson2JsonRedisSerializer;
    }

    private boolean checkValue(String value) {
        JsonNode dataNode;
        try {
            if (!value.startsWith("{")) {
                return true;
            }
            dataNode = objectMapper.readTree(value);
            int code = dataNode.get("code").intValue();
            return code == 200;
        } catch (JsonProcessingException e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return false;
        }
    }
}
