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

package com.om.omwebserver;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.cache.RedisCacheWriter;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.scheduling.annotation.EnableAsync;

import com.om.Modules.TtlRedisCacheManager;

@SpringBootApplication
@ComponentScan(basePackages = {"com.om.*"})
@EnableAsync
@EnableCaching
public class OmWebserverApplication {
    /**
     * Spring缓存的TTL值.
     */
    @Value("${spring.cache.ttl}")
    private String springCacheTtl;


    /**
     * 应用程序的入口点，启动 Spring Boot 应用.
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        SpringApplication.run(OmWebserverApplication.class, args);
    }

    /**
     * 配置 TTL 缓存管理器 Bean.
     *
     * @param redisConnectionFactory Redis 连接工厂
     * @return TTL 缓存管理器实例
     */
    @Bean
    public RedisCacheManager ttlCacheManager(RedisConnectionFactory redisConnectionFactory) {
        RedisCacheConfiguration defaultCacheConfig = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofDays(Long.parseLong(springCacheTtl)));

        return new TtlRedisCacheManager(RedisCacheWriter.lockingRedisCacheWriter(redisConnectionFactory),
                defaultCacheConfig);
    }
}
