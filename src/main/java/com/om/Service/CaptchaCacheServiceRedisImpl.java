package com.om.Service;

import com.anji.captcha.service.CaptchaCacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class CaptchaCacheServiceRedisImpl implements CaptchaCacheService {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @Override
    public void set(String s, String s1, long l) {
        stringRedisTemplate.opsForValue().set(s, s1, l, TimeUnit.SECONDS);
    }

    @Override
    public boolean exists(String s) {
        return stringRedisTemplate.hasKey(s);
    }

    @Override
    public void delete(String s) {
        stringRedisTemplate.delete(s);
    }

    @Override
    public String get(String s) {
        return stringRedisTemplate.opsForValue().get(s);
    }

    @Override
    public String type() {
        return "redis";
    }
}
