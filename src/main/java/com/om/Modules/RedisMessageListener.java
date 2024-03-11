package com.om.Modules;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;

public class RedisMessageListener implements MessageListener {

    private static final Logger logger = LoggerFactory.getLogger(RedisMessageListener.class);

    /**
     * Redis 事件监听回调
     * @param message
     * @param pattern
     */
    @Override
    public void onMessage(Message message, byte[] pattern) {
        byte[] body = message.getBody();
        String expiredKey = new String(body);
        if (expiredKey.contains("loginCount")) {
            logger.info(String.format("Account %s is unlocked", expiredKey.replace("loginCount", "")));
        }
    }
}
