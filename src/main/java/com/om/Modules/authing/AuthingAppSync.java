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

package com.om.Modules.authing;

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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AuthingAppSync {
    private static final Logger logger =  LoggerFactory.getLogger(AuthingAppSync.class);

    private static final int APP_LIST_PAGE_MAX = 100;

    @Value("${authing.userPoolId}")
    private String userPoolId;

    @Value("${authing.secret}")
    private String secret;

    @Autowired
    @Qualifier("SR-Task-SchedulePool")
    private ThreadPoolTaskScheduler taskPool;

    private static ApplicationManagementClient appManagementClient;

    private static ConcurrentHashMap<String, Application> appDetailsMap = new ConcurrentHashMap<>();

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
                if (StringUtils.isNotBlank(app.getId())) {
                    appIds.add(app.getId());
                    appDetailsMap.put(app.getId(), app);
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
            logger.warn("App list is null.");
        }
    }

    private List<Application> getAllAppList() {
        List<Application> applications = new ArrayList<>();
        for (int i = 1;;i++) {
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
            logger.error("Get app list failed: {}", e.getMessage());
            return null;
        }
    }

    public Application getAppById(String id) {
        if (appDetailsMap.isEmpty()) {
            appDetailsSync();
        }
        return appDetailsMap.get(id);
    }

    public List<String> getAppRedirectUris(String appId) {
        List<String> redirectUris = new ArrayList<>();
        Application execute = getAppById(appId);
        if (execute != null) {
            redirectUris = execute.getRedirectUris();
        }
        return redirectUris;
    }
}
