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
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.stereotype.Repository;


/**
 * @author zhxia
 * @date 2020/11/16 14:37
 */
@Repository
public class RedisDao {
    @Autowired
    protected StringRedisTemplate redisTemplate;

    static ObjectMapper objectMapper = new ObjectMapper();

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
            if (!checkValue(value)) return false;
            redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
            ValueOperations operations = redisTemplate.opsForValue();
            operations.set(key, value);
            if (expire < 1)
                redisTemplate.persist(key);
            else
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
        redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
        try {
            ValueOperations operations = redisTemplate.opsForValue();
            result = operations.get(key);
        } catch (Exception e) {
            System.out.println(e);
        }
        return result;
    }

    /**
     * redis hash
     */
    public boolean set(final String key, String field, String value, Long expire) {
        boolean result = false;
        try {
            if (!checkValue(value))
                return false;
            redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
            HashOperations<String, String, String> map = redisTemplate.opsForHash();
            map.put(key, field, value);
            redisTemplate.expire(key, expire, TimeUnit.SECONDS);
            result = true;
        } catch (Exception e) {
            System.out.println(e);
        }
        return result;
    }

    public Object get(final String key, String field) {
        Object result = null;
        redisTemplate.setValueSerializer(new GzipSerializer(getJsonserializer()));
        try {
            HashOperations<String, String, String> hashOperations = redisTemplate.opsForHash();
            result = hashOperations.get(key, field);
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

    class GzipSerializer implements RedisSerializer<Object> {

        public static final int BUFFER_SIZE = 4096;
        // 这里组合方式，使用到了一个序列化器
        private RedisSerializer<Object> innerSerializer;

        public GzipSerializer(RedisSerializer<Object> innerSerializer) {
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
            if (!value.startsWith("{")) return true;
            dataNode = objectMapper.readTree(value);
            int code = dataNode.get("code").intValue();
            return code == 200;
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return false;
        }
    }
}
