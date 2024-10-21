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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Dao.RedisDao;
import com.om.Result.Constant;
import com.om.Service.bean.OnlineUserInfo;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Service
public class OnlineUserManager {
    /**
     * 日志.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OnlineUserManager.class);

    /**
     * 退出APP线程池.
     */
    private static final ExecutorService LOGOUT_EXE = new ThreadPoolExecutor(4, 5,
            60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(10000));

    /**
     * ObjectMapper实例.
     */
    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 用于与 Redis 数据库进行交互的 DAO.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 应用程序的环境配置.
     */
    @Autowired
    private Environment env;

    /**
     * 校验登录状态.
     *
     * @param verifyToken token
     * @param userId 用户id
     * @return 是否处于登录
     */
    public boolean isLoginNormal(String verifyToken, String userId) {
        String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(userId).toString();
        String tokenKey = Constant.ID_TOKEN_PREFIX + verifyToken;
        String idToken = (String) redisDao.get(tokenKey);
        List<String> onlineUsers = redisDao.getListValue(loginKey);
        if (CollectionUtils.isEmpty(onlineUsers)) {
            return false;
        }
        boolean isContain = false;
        try {
            for (String userJson : onlineUsers) {
                OnlineUserInfo onlineUserInfo = new OnlineUserInfo();
                if (userJson.startsWith("{")) {
                    onlineUserInfo = objectMapper.readValue(userJson, OnlineUserInfo.class);
                } else {
                    onlineUserInfo.setIdToken(userJson);
                }
                if (StringUtils.equals(idToken, onlineUserInfo.getIdToken())) {
                    isContain = true;
                    break;
                }
            }
        } catch (JsonProcessingException e) {
            LOGGER.error("parse json failed {}", e.getMessage());
        }
        if (!isContain) {
            return false;
        }
        int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
        redisDao.setKeyExpire(loginKey, expireSeconds);
        return true;
    }

    /**
     * 限制单个用户会话数量.
     *
     * @param userId 用户ID
     * @param idToken idtoken
     * @param maxLoginNum 最大会话数量
     */
    public void limitLoginNum(String userId, String idToken, Integer maxLoginNum) {
        String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(userId).toString();
        int expireSeconds = Integer.parseInt(env.getProperty("authing.token.expire.seconds", "120"));
        redisDao.addList(loginKey, idToken, expireSeconds);
        long listSize = redisDao.getListSize(loginKey);
        if (listSize > maxLoginNum) {
            redisDao.removeListTail(loginKey, maxLoginNum);
        }
    }

    /**
     * 移除用户单个会话.
     *
     * @param userId 用户ID
     * @param idToken idtoken
     */
    public void removeSession(String userId, String idToken) {
        try {
            String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER)
                    .append(userId).toString();
            List<String> userList = redisDao.getListValue(loginKey);
            if (CollectionUtils.isEmpty(userList)) {
                return;
            }
            for (String userJson : userList) {
                OnlineUserInfo onlineUserInfo = new OnlineUserInfo();
                if (userJson.startsWith("{")) {
                    onlineUserInfo = objectMapper.readValue(userJson, OnlineUserInfo.class);
                } else {
                    onlineUserInfo.setIdToken(userJson);
                }
                if (StringUtils.equals(idToken, onlineUserInfo.getIdToken())) {
                    logoutApps(idToken, onlineUserInfo.getLogoutUrls());
                    redisDao.removeListValue(loginKey, userJson);
                    break;
                }
            }
        } catch (JsonProcessingException e) {
            LOGGER.error("parse json failed {}", e.getMessage());
        }
    }

    /**
     * 移除当前用户所有会话.
     * @param userId 用户ID
     */
    public void removeAllSessions(String userId) {
        if (StringUtils.isNotBlank(userId)) {
            String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER)
                    .append(userId).toString();
            redisDao.remove(loginKey);
        }
    }

    /**
     * 增加子服务的退出登录url.
     *
     * @param userId 用户ID
     * @param idToken idtoken
     * @param logoutUrl 退出登录url
     */
    public void addServiceLogoutUrl(String userId, String idToken, String logoutUrl) {
        if (StringUtils.isAnyBlank(userId, idToken, logoutUrl)) {
            return;
        }
        try {
            String loginKey = new StringBuilder().append(Constant.REDIS_PREFIX_LOGIN_USER).append(userId).toString();
            List<String> userList = redisDao.getListValue(loginKey);
            if (CollectionUtils.isEmpty(userList)) {
                return;
            }

            for (int i = 0; i < userList.size(); i++) {
                OnlineUserInfo onlineUserInfo = new OnlineUserInfo();
                String userJson = userList.get(i);
                if (userJson.startsWith("{")) {
                    onlineUserInfo = objectMapper.readValue(userJson, OnlineUserInfo.class);
                } else {
                    onlineUserInfo.setIdToken(userJson);
                }
                if (onlineUserInfo.getLogoutUrls() == null) {
                    onlineUserInfo.setLogoutUrls(new HashSet<>());
                }
                if (StringUtils.equals(idToken, onlineUserInfo.getIdToken())) {
                    onlineUserInfo.getLogoutUrls().add(logoutUrl);
                    redisDao.updateListValue(loginKey, i, objectMapper.writeValueAsString(onlineUserInfo));
                    break;
                }
            }
        } catch (JsonProcessingException e) {
            LOGGER.error("add oidc logout url parse json failed {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.error("add oidc logout url failed {}", e.getMessage());
        }
    }

    private void logoutApps(String idToken, Set<String> logoutUrls) {
        if (CollectionUtils.isEmpty(logoutUrls)) {
            return;
        }
        for (String logoutUrl : logoutUrls) {
            LOGOUT_EXE.submit(() -> {
                try {
                    HttpResponse<JsonNode> response = Unirest.get(logoutUrl)
                            .header("Authorization", idToken)
                            .asJson();
                    if (response.getStatus() != 200) {
                        LOGGER.error("logout app failed {} {}", logoutUrl, response.getStatus());
                    }
                } catch (Exception e) {
                    LOGGER.error("logout app failed {} {}", logoutUrl, e.getMessage());
                }
            });
        }
    }
}
