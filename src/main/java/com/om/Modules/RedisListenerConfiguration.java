package com.om.Modules;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.PatternTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.Topic;

/**
 * Redis监听器配置类.
 */
@Configuration
public class RedisListenerConfiguration {
    /**
     * 用于监听的 Redis 模式，默认为 "__keyevent@0__:expired".
     */
    @Value("${spring.data.redis.listen-pattern}")
    private String pattern;

    /**
     * 创建用于监听 Redis 消息的容器.
     *
     * @param redisConnection Redis连接工厂
     * @return Redis消息监听器容器
     */
    @Bean
    public RedisMessageListenerContainer listenerContainer(RedisConnectionFactory redisConnection) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(redisConnection);

        //Topic是消息发布(Pub)者和订阅(Sub)者之间的传输中介
        Topic topic = new PatternTopic(this.pattern);

        container.addMessageListener(new RedisMessageListener(), topic);
        return container;
    }
}
