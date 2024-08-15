/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.Service;

import com.anji.captcha.service.CaptchaCacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class CaptchaCacheServiceRedisImpl implements CaptchaCacheService {
    /**
     * 注入 StringRedisTemplate 依赖.
     */
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 将键值对存入 Redis，并设置过期时间.
     *
     * @param s  键
     * @param s1 值
     * @param l  过期时间（秒）
     */
    @Override
    public void set(String s, String s1, long l) {
        stringRedisTemplate.opsForValue().set(s, s1, l, TimeUnit.SECONDS);
    }

    /**
     * 检查指定键是否存在于 Redis 中.
     *
     * @param s 键
     * @return 若键存在返回 true，否则返回 false
     */
    @Override
    public boolean exists(String s) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(s));
    }

    /**
     * 从 Redis 删除指定键的数据.
     *
     * @param s 键
     */
    @Override
    public void delete(String s) {
        stringRedisTemplate.delete(s);
    }

    /**
     * 根据键获取 Redis 中的值.
     *
     * @param s 键
     * @return 对应键的值
     */
    @Override
    public String get(String s) {
        return stringRedisTemplate.opsForValue().get(s);
    }

    /**
     * 返回缓存类型.
     *
     * @return 缓存类型为 "redis"
     */
    @Override
    public String type() {
        return "redis";
    }
}
