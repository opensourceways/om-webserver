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

package com.om.modules.authing;

import cn.authing.core.auth.AuthenticationClient;
import cn.authing.core.mgmt.ApplicationManagementClient;
import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.Application;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;


import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AuthingAppSync {
    /**
     * 认证应用同步类的日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingAppSync.class);

    /**
     * 应用列表每页最大数量常量.
     */
    private static final int APP_LIST_PAGE_MAX = 100;

    /**
     * Authing 用户池ID.
     */
    @Value("${authing.userPoolId}")
    private String userPoolId;

    /**
     * Authing 密钥.
     */
    @Value("${authing.secret}")
    private String secret;

    /**
     * 定时任务线程池.
     */
    @Autowired
    @Qualifier("SR-Task-SchedulePool")
    private ThreadPoolTaskScheduler taskPool;

    /**
     * 应用管理客户端.
     */
    private static ApplicationManagementClient appManagementClient;

    /**
     * 应用详情映射.
     */
    private static ConcurrentHashMap<String, Application> appDetailsMap = new ConcurrentHashMap<>();

    /**
     * 应用客户端映射.
     */
    private static Map<String, AuthenticationClient> appClientMap = new ConcurrentHashMap<>();

    @PostConstruct
    private void init() {
        appManagementClient = new ManagementClient(userPoolId, secret).application();
        taskPool.schedule(this::appDetailsSync, new CronTrigger("0 2/10 * * * ?"));
    }

    private synchronized void appDetailsSync() {
        List<Application> applications = getAllAppList();
        if (!CollectionUtils.isEmpty(applications)) {
            List<String> appIds = new ArrayList<>();
            applications.forEach(app -> {
                String appId = app.getId();
                if (StringUtils.isNotBlank(appId)) {
                    appIds.add(appId);
                    appDetailsMap.put(appId, app);
                }
                if (!appClientMap.containsKey(appId)) {
                    String appHost = "https://" + app.getIdentifier() + ".authing.cn";
                    AuthenticationClient appClient = new AuthenticationClient(appId, appHost);
                    appClient.setSecret(app.getSecret());
                    appClientMap.put(appId, appClient);
                }
            });
            Iterator<Map.Entry<String, Application>> iterator = appDetailsMap.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, Application> entry = iterator.next();
                if (!appIds.contains(entry.getKey())) {
                    iterator.remove();
                }
            }
        } else {
            LOGGER.warn("App list is null.");
        }
    }

    private List<Application> getAllAppList() {
        List<Application> applications = new ArrayList<>();
        for (int i = 1; ; i++) {
            List<Application> appList = getAppList(i, APP_LIST_PAGE_MAX);
            if (CollectionUtils.isEmpty(appList)) {
                break;
            }
            applications.addAll(appList);
            if (appList.size() < APP_LIST_PAGE_MAX) {
                break;
            }
        }
        return applications;
    }

    private List<Application> getAppList(int pageNo, int pageSize) {
        try {
            return appManagementClient.list(pageNo, pageSize).execute();
        } catch (Exception e) {
            LOGGER.error("Get app list failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 根据应用ID获取应用信息.
     *
     * @param id 应用ID
     * @return 应用对象
     */
    public Application getAppById(String id) {
        if (appDetailsMap.isEmpty()) {
            appDetailsSync();
        }
        return appDetailsMap.get(id);
    }

    /**
     * 根据应用ID获取应用客户端.
     *
     * @param id 应用ID
     * @return 应用客户端对象
     */
    public AuthenticationClient getAppClientById(String id) {
        if (appClientMap.isEmpty()) {
            appDetailsSync();
        }
        return appClientMap.get(id);
    }

    /**
     * 获取应用重定向URI列表.
     *
     * @param appId 应用ID
     * @return 应用重定向URI列表
     */
    public List<String> getAppRedirectUris(String appId) {
        List<String> redirectUris = new ArrayList<>();
        Application execute = getAppById(appId);
        if (execute != null) {
            redirectUris = execute.getRedirectUris();
        }
        return redirectUris;
    }
}
