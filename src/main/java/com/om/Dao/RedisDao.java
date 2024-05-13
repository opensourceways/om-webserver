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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.om.Modules.MessageCodeConfig;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
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
        return redisTemplate.opsForValue().getOperations().getExpire(key);
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
            result = redisTemplate.hasKey(key);
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

    class GzipSerializer implements RedisSerializer<Object> {

        /**
         * 缓冲区大小常量.
         */
        public static final int BUFFER_SIZE = 4096;
        /**
         * 这里组合方式，使用到了一个序列化器.
         */
        private RedisSerializer<Object> innerSerializer;

        GzipSerializer(RedisSerializer<Object> innerSerializer) {
            this.innerSerializer = innerSerializer;
        }

        @Override
        public byte[] serialize(Object graph) throws SerializationException {
            if (graph == null) {
                return new byte[0];
            }
            ByteArrayOutputStream bos = null;
            GZIPOutputStream gzip = null;
            try {
                // 先序列化
                byte[] bytes = innerSerializer.serialize(graph);
                bos = new ByteArrayOutputStream();
                gzip = new GZIPOutputStream(bos);
                // 在压缩
                gzip.write(bytes);
                gzip.finish();
                byte[] result = bos.toByteArray();
                return result;
            } catch (Exception e) {
                LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
                throw new SerializationException("Gzip Serialization Error", e);
            } finally {
                IOUtils.closeQuietly(bos);
                IOUtils.closeQuietly(gzip);
            }
        }

        @Override
        public Object deserialize(byte[] bytes) throws SerializationException {

            if (bytes == null || bytes.length == 0) {
                return null;
            }

            ByteArrayOutputStream bos = null;
            ByteArrayInputStream bis = null;
            GZIPInputStream gzip = null;
            try {
                bos = new ByteArrayOutputStream();
                bis = new ByteArrayInputStream(bytes);
                gzip = new GZIPInputStream(bis);
                byte[] buff = new byte[BUFFER_SIZE];
                int n;
                // 先解压
                while ((n = gzip.read(buff, 0, BUFFER_SIZE)) > 0) {
                    bos.write(buff, 0, n);
                }
                // 再反序列化
                Object result = innerSerializer.deserialize(bos.toByteArray());
                return result;
            } catch (Exception e) {
                LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
                throw new SerializationException("Gzip deserizelie error", e);
            } finally {
                IOUtils.closeQuietly(bos);
                IOUtils.closeQuietly(bis);
                IOUtils.closeQuietly(gzip);

            }
        }
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
