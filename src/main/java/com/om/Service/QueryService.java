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

package com.om.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;

import com.om.Modules.MessageCodeConfig;
import org.apache.commons.lang3.StringUtils;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.Objects;


@Service
public class QueryService {
    /**
     * 自动注入 QueryDao 对象.
     */
    @Autowired
    private QueryDao queryDao;

    /**
     * 自动注入 RedisDao 对象.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 自动注入环境变量.
     */
    @Autowired
    private Environment env;

    /**
     * 自动注入 AuthingUserDao 对象.
     */
    @Autowired
    private AuthingUserDao authingUserDao;

    /**
     * 日志记录器，用于记录 QueryService 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(QueryService.class);


    /**
     * 查询用户所有者类型.
     *
     * @param community 社区
     * @param user      用户
     * @param username  用户名
     * @return 用户所有者类型的字符串
     * @throws JsonProcessingException JSON处理异常
     */
    public String queryUserOwnertype(String community, String user, String username)
            throws JsonProcessingException {
        String key = community.toLowerCase() + user + "ownertype";
        String result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryUserOwnertype(community, user);
            } catch (Exception e) {
                LOGGER.error(MessageCodeConfig.E00048.getMsgEn(), e);
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }

        String giteeLogin = StringUtils.isNotBlank(user) ? user.toLowerCase() : getGiteeLoginFromAuthing(username);
        result = queryDao.queryUserOwnertype(community, giteeLogin);
        return result;
    }

    private String getGiteeLoginFromAuthing(String username) {
        String giteeLogin = "";
        if (StringUtils.isBlank(username)) {
            return giteeLogin;
        }
        try {
            JSONObject userInfo = authingUserDao.getUserByName(username);
            JSONArray identities = userInfo.getJSONArray("identities");
            for (Object identity : identities) {
                JSONObject identityObj = (JSONObject) identity;
                String originConnId = identityObj.getJSONArray("originConnIds").get(0).toString();
                if (!originConnId.equals(env.getProperty("enterprise.connId.gitee"))) {
                    continue;
                }
                giteeLogin = identityObj.getJSONObject("userInfoInIdp").getJSONObject("customData")
                        .getString("giteeLogin");
            }
        } catch (Exception ignored) {
        }
        return giteeLogin;
    }

}

