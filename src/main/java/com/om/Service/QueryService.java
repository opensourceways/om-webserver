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

// import com.auth0.jwt.JWT;
// import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
// import com.fasterxml.jackson.core.type.TypeReference;
// import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.AuthingUserDao;
import com.om.Dao.QueryDao;
import com.om.Dao.RedisDao;
import java.util.*;

import com.om.Modules.MessageCodeConfig;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;


/**
 * @author zhxia
 * @date 2020/10/22 11:40
 */
@Service
public class QueryService {
    @Autowired
    QueryDao queryDao;

    @Autowired
    RedisDao redisDao;

    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    private static final Logger logger =  LoggerFactory.getLogger(QueryService.class);

    public String queryUserOwnertype(String community, String user, String username)
            throws JsonProcessingException {
        String key = community.toLowerCase() + "all" + "ownertype";
        String result = null;
        result = (String) redisDao.get(key);
        if (result == null) {
            // 查询数据库，更新redis 缓存。
            try {
                result = queryDao.queryAllUserOwnertype(community);
            } catch (Exception e) {
                logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            }
            boolean set = redisDao.set(key, result,
                    Long.valueOf(Objects.requireNonNull(env.getProperty("spring.redis.key.expire"))));
            if (set) {
                System.out.println("update " + key + " success!");
            }
        }

        String giteeLogin = StringUtils.isNotBlank(user) ? user.toLowerCase() : getGiteeLoginFromAuthing(username);

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode all = objectMapper.readTree(result);
        JsonNode userData = all.get("data").get(giteeLogin);
        if (userData != null) {
            result = objectMapper.valueToTree(userData).toString();
        } else {
            result = "[]";
        }
        result = "{\"code\":200,\"data\":" + result + ",\"msg\":\"ok\"}";
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
                if (!originConnId.equals(env.getProperty("enterprise.connId.gitee"))) continue;
                giteeLogin = identityObj.getJSONObject("userInfoInIdp").getJSONObject("customData")
                        .getString("giteeLogin");
            }
        } catch (Exception ignored) {
        }
        return giteeLogin;
    }

}

