package com.om.Dao;

import com.om.Modules.MessageCodeConfig;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Objects;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

class GzipSerializer implements RedisSerializer<Object> {

    /**
     * 日志记录器实例，用于记录 AuthingUserDao 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingUserDao.class);

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
            if (Objects.nonNull(bytes)) {
                gzip.write(bytes);
            }
            gzip.finish();
            byte[] result = bos.toByteArray();
            return result;
        } catch (Exception e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
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
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            throw new SerializationException("Gzip deserizelie error", e);
        } finally {
            IOUtils.closeQuietly(bos);
            IOUtils.closeQuietly(bis);
            IOUtils.closeQuietly(gzip);

        }
    }
}
