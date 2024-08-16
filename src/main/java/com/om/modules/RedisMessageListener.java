package com.om.modules;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;

import java.nio.charset.StandardCharsets;

/**
 * Redis 消息监听器类实现消息监听接口.
 */
public class RedisMessageListener implements MessageListener {
    /**
     * 静态日志记录器，用于记录 RedisMessageListener 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RedisMessageListener.class);

    /**
     * 处理接收到的消息.
     *
     * @param message 接收到的消息
     * @param pattern 匹配模式
     */
    @Override
    public void onMessage(Message message, byte[] pattern) {
        byte[] body = message.getBody();
        String expiredKey = new String(body, StandardCharsets.UTF_8);
        if (expiredKey.contains("loginCount")) {
            LOGGER.info(String.format("Account %s is unlocked", expiredKey.replace("loginCount", "")));
        }
    }
}
