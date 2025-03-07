/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2025
*/

package com.om.modules.authing;

import cn.authing.core.types.ResourcePermissionAssignment;
import com.om.controller.bean.request.BatchAuthInfo;
import com.om.dao.AuthingManagerDao;
import com.om.dao.RedisDao;
import com.om.dao.bean.AuthorizeInfo;
import com.om.dao.bean.UserInfo;
import com.om.modules.bean.GitCodePermissionInfo;
import com.om.utils.CodeUtil;
import com.om.utils.CommonUtil;
import com.om.utils.LogUtil;
import jakarta.annotation.PostConstruct;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
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

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class AuthingResourceSync {
    /**
     * 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingResourceSync.class);

    /**
     * CodeUtil实例.
     */
    private CodeUtil codeUtil = new CodeUtil();

    /**
     * gitcode 操作权限.
     */
    private List<String> gitcodeActions;

    /**
     * GitCode 企业登录的外部身份提供者 ID.
     */
    @Value("${enterprise.extIdpId.gitcode: }")
    private String enterExtIdpIdGitCode;

    /**
     * GitCode 企业登录的源 ID.
     */
    @Value("${enterprise.connId.gitcode: }")
    private String enterConnIdGitCode;

    /**
     * gitcode namesapce.
     */
    @Value("${authing.permission.gitcodeRepo.namespace: }")
    private String gitcodeRepoNamesapce;

    /**
     * gitcode actions.
     */
    @Value("${authing.permission.gitcodeRepo.actions: }")
    private String gitcodeRepoActions;

    /**
     * gitcode info url.
     */
    @Value("${authing.permission.gitcodeRepo.remoteUrl: }")
    private String gitcodeRepoUrl;

    /**
     * 分布式锁.
     */
    @Value("${authing.permission.gitcodeRepo.lockKey: }")
    private String gitcodeLockKey;

    /**
     * 分布式锁.
     */
    @Value("${authing.permission.gitcodeRepo.identifier: }")
    private String gitcodeLockIdentifier;

    /**
     * 锁的时长.
     */
    @Value("${authing.permission.gitcodeRepo.expireTime: }")
    private Integer gitcodeLockExpireTime;

    /**
     * 定时任务线程池.
     */
    @Autowired
    @Qualifier("SR-Task-SchedulePool")
    private ThreadPoolTaskScheduler taskPool;

    /**
     * 管理面dao.
     */
    @Autowired
    private AuthingManagerDao authingManagerDao;

    /**
     * 使用 @Autowired 注解注入 RedisDao.
     */
    @Autowired
    private RedisDao redisDao;

    @PostConstruct
    private void init() {
        if (StringUtils.isNotBlank(gitcodeRepoNamesapce)) {
            gitcodeActions = Arrays.asList(gitcodeRepoActions.split(","));
            taskPool.schedule(this::gitCodeRepoPerSync, new CronTrigger("0 10 0/1 * * ?"));
        }
    }

    private synchronized void gitCodeRepoPerSync() {
        if (!redisDao.acquireLock(gitcodeLockKey, gitcodeLockIdentifier, gitcodeLockExpireTime)) {
            LOGGER.warn("gitcode repo permissions sync has been running on other pod");
            return;
        }
        LOGGER.info("gitcode repo permissions sync start");
        try {
            List<GitCodePermissionInfo> gitcodePerDatas = new ArrayList<>();
            Map<String, String> gitcodeUserMap = new HashMap<>();
            getRepoUserInfo(gitcodePerDatas, gitcodeUserMap);
            for (GitCodePermissionInfo gitCodePermissionInfo : gitcodePerDatas) {
                Set<String> gitcodeUserIds = gitCodePermissionInfo.getUserIds();
                if (CollectionUtils.isEmpty(gitcodeUserIds)) {
                    continue;
                }
                if (!authingManagerDao.createResource(gitcodeRepoNamesapce, gitCodePermissionInfo.getResource(),
                        gitcodeActions)) {
                    LOGGER.error("auto create resource {} failed",  gitCodePermissionInfo.getResource());
                    continue;
                }
                List<UserInfo> allUserInfos = new ArrayList<>();
                List<List<String>> gitcodeUserIdSplit = CommonUtil.splitList(gitcodeUserIds.stream().toList(), 50);
                for (List<String> userIds : gitcodeUserIdSplit) {
                    List<UserInfo> userInfos = authingManagerDao.getUsersByIds("identity",
                            enterExtIdpIdGitCode, userIds);
                    allUserInfos.addAll(userInfos);
                }

                if (allUserInfos == null) {
                    LOGGER.error("sync gitcode repo {} permissions failed: get userinfo failed",
                            gitCodePermissionInfo.getResource());
                    continue;
                }
                List<String> createUserIds = gitcodeUserIds.stream().collect(Collectors.toList());
                        // 去掉已经获取基本信息的用户
                allUserInfos.forEach(userInfo -> {
                    if (createUserIds.contains(userInfo.getUserIdInIdp())) {
                        createUserIds.remove(userInfo.getUserIdInIdp());
                    }
                });
                List<UserInfo> userInfoCreated = new ArrayList<>();
                if (!CollectionUtils.isEmpty(createUserIds)) {
                    for (String gitcodeUserId : createUserIds) {
                        JSONObject userObj = createUserObj(gitcodeUserMap.get(gitcodeUserId), gitcodeUserId);
                        UserInfo user = authingManagerDao.createUser(userObj);
                        if (user == null) {
                            LogUtil.createLogs(gitcodeUserMap.get(gitcodeUserId), "auto register", "register",
                                    "auto create user", "localhost", "failed");
                        } else {
                            userInfoCreated.add(user);
                            LogUtil.createLogs(user.getUsername(), "auto register", "register",
                                    "auto create user", "localhost", "success");
                        }
                    }
                    LOGGER.info("sync gitcode needs to create {} users, and has created {} users",
                            createUserIds.size(), userInfoCreated.size());
                }
                List<String> authUsers = new ArrayList<>();
                authUsers.addAll(allUserInfos.stream().map(UserInfo::getUserId).collect(Collectors.toList()));
                authUsers.addAll(userInfoCreated.stream().map(UserInfo::getUserId).collect(Collectors.toList()));
                BatchAuthInfo batchAuthInfo = new BatchAuthInfo();
                batchAuthInfo.setNamespaceCode(gitcodeRepoNamesapce);
                batchAuthInfo.setIsDeleteOthers(true);
                batchAuthInfo.setUserIds(authUsers);
                batchAuthInfo.setResource(gitCodePermissionInfo.getResource());
                batchAuthInfo.setActions(gitCodePermissionInfo.getActions());
                if (!batchAuthrize(batchAuthInfo)) {
                    LOGGER.error("sync gitcode repo {} permissions failed: batch auth failed",
                            gitCodePermissionInfo.getResource());
                }
            }
        } catch (Exception e) {
            LOGGER.error("gitcode permission sync failed {}", e.getMessage());
        }
        LOGGER.info("gitcode repo permissions sync end");
    }

    private void getRepoUserInfo(List<GitCodePermissionInfo> gitcodePerDatas, Map<String, String> userMap) {
        JSONArray permissions = getRemoteData();
        for (int i = 0; i < permissions.length(); i++) {
            List<String> repos = new ArrayList<>();
            Set<String> maintainers = new HashSet<>();
            Set<String> committers = new HashSet<>();
            JSONObject permissionObject = permissions.getJSONObject(i);
            JSONArray repoArray = permissionObject.getJSONArray("repos");
            if (repoArray == null) {
                continue;
            }
            for (int j = 0; j < repoArray.length(); j++) {
                String[] repoStrs = repoArray.getString(j).split("/");
                repos.add(repoStrs[1]);
            }
            parseRepoManager(userMap, permissionObject, maintainers, committers);

            if (!permissionObject.has("repo_developers") || permissionObject.isNull("repo_developers")) {
                continue;
            }

            JSONObject developerInfo = permissionObject.getJSONObject("repo_developers");
            if (developerInfo != null) {
                for (String repo : repos) {
                    GitCodePermissionInfo perfMaintainers = new GitCodePermissionInfo();
                    perfMaintainers.setResource(repo);
                    perfMaintainers.setActions(List.of("maintainer"));
                    perfMaintainers.setUserIds(maintainers);
                    gitcodePerDatas.add(perfMaintainers);
                    GitCodePermissionInfo perfCommiters = new GitCodePermissionInfo();
                    perfCommiters.setResource(repo);
                    perfCommiters.setActions(List.of("committer"));
                    perfCommiters.setUserIds(committers);
                    gitcodePerDatas.add(perfCommiters);
                    JSONArray developerArray = developerInfo.getJSONArray(repo);
                    if (developerArray == null) {
                        continue;
                    }
                    Set<String> developers = new HashSet<>();
                    for (int j = 0; j < developerArray.length(); j++) {
                        if (!developerArray.getJSONObject(j).has("gitcode_id")
                                || developerArray.getJSONObject(j).isNull("gitcode_id")
                                || !developerArray.getJSONObject(j).has("user_id")
                                || developerArray.getJSONObject(j).isNull("user_id")) {
                            continue;
                        }
                        String gitcodeId = developerArray.getJSONObject(j).getString("gitcode_id");
                        String userId = developerArray.getJSONObject(j).getString("user_id");
                        userMap.put(userId, gitcodeId);
                        developers.add(userId);
                    }
                    GitCodePermissionInfo perfDevelopers = new GitCodePermissionInfo();
                    perfDevelopers.setResource(repo);
                    perfDevelopers.setActions(List.of("repo_developer"));
                    perfDevelopers.setUserIds(developers);
                    gitcodePerDatas.add(perfDevelopers);
                }
            }
        }
    }

    private void parseRepoManager(Map<String, String> userMap, JSONObject permissionObject,
                                         Set<String> maintainers, Set<String> committers) {
        if (permissionObject.has("maintainers") && !permissionObject.isNull("maintainers")) {
            JSONArray maintainerArray = permissionObject.getJSONArray("maintainers");
            if (maintainerArray != null) {
                for (int j = 0; j < maintainerArray.length(); j++) {
                    if (!maintainerArray.getJSONObject(j).has("gitcode_id")
                            || maintainerArray.getJSONObject(j).isNull("gitcode_id")
                            || !maintainerArray.getJSONObject(j).has("user_id")
                            || maintainerArray.getJSONObject(j).isNull("user_id")) {
                        continue;
                    }
                    String gitcodeId = maintainerArray.getJSONObject(j).getString("gitcode_id");
                    String userId = maintainerArray.getJSONObject(j).getString("user_id");
                    userMap.put(userId, gitcodeId);
                    maintainers.add(userId);
                }
            }
        }

        if (permissionObject.has("committers") && !permissionObject.isNull("committers")) {
            JSONArray committerArray = permissionObject.getJSONArray("committers");
            if (committerArray != null) {
                for (int j = 0; j < committerArray.length(); j++) {
                    if (!committerArray.getJSONObject(j).has("gitcode_id")
                            || committerArray.getJSONObject(j).isNull("gitcode_id")
                            || !committerArray.getJSONObject(j).has("user_id")
                            || committerArray.getJSONObject(j).isNull("user_id")) {
                        continue;
                    }
                    String gitcodeId = committerArray.getJSONObject(j).getString("gitcode_id");
                    String userId = committerArray.getJSONObject(j).getString("user_id");
                    userMap.put(userId, gitcodeId);
                    committers.add(userId);
                }
            }
        }
    }

    private JSONArray getRemoteData() {
        JSONArray data = new JSONArray();
        try {
            HttpResponse<JsonNode> response = Unirest.get(gitcodeRepoUrl).asJson();
            if (response.getStatus() == 200) {
                data = response.getBody().getObject().getJSONArray("data");
            } else {
                LOGGER.error("get gitcode remote userinfo failed {}", response.getBody().getObject());
            }
        } catch (Exception e) {
            LOGGER.error("get gitcode remote userinfo failed {}", e.getMessage());
        }
        return data;
    }

    private JSONObject createUserObj(String identName, String identId) throws NoSuchAlgorithmException {
        JSONObject userObj = new JSONObject();
        StringBuilder userName = new StringBuilder(identName);
        userName.append("_").append(codeUtil.randomStrBuilder(5));
        userObj.put("username", userName);
        JSONObject identitiesObj = new JSONObject();
        List<JSONObject> identities = new ArrayList<>();
        JSONObject userInfoInIdpObj = new JSONObject();
        userInfoInIdpObj.put("name", identName);
        identitiesObj.put("extIdpId", enterExtIdpIdGitCode);
        identitiesObj.put("provider", "oauth2");
        identitiesObj.put("type", "generic");
        identitiesObj.put("userIdInIdp", identId);
        identitiesObj.put("userInfoInIdp", userInfoInIdpObj);
        List<String> originConnIds = new ArrayList<>();
        originConnIds.add(enterConnIdGitCode);
        identitiesObj.put("originConnIds", originConnIds);
        identities.add(identitiesObj);
        userObj.put("identities", identities);
        return userObj;
    }

    /**
     * 批量授权.
     *
     * @param batchAuthInfo 权限信息
     * @return 授权结果
     */
    public boolean batchAuthrize(BatchAuthInfo batchAuthInfo) {
        try {
            if (CollectionUtils.isEmpty(batchAuthInfo.getUserIds())) {
                return true;
            }
            List<ResourcePermissionAssignment> authorizedUsers = authingManagerDao.getAuthorizedUser(
                    batchAuthInfo.getNamespaceCode(),
                    batchAuthInfo.getResource(), batchAuthInfo.getActions());
            List<String> authUserIds = authorizedUsers.stream()
                    .map(ResourcePermissionAssignment::getTargetIdentifier).collect(Collectors.toList());
            if (batchAuthInfo.getIsDeleteOthers()) {
                List<String> deleteUserIds = new ArrayList<>();
                for (String userId : authUserIds) {
                    if (!batchAuthInfo.getUserIds().contains(userId)) {
                        deleteUserIds.add(userId);
                    }
                }
                if (!CollectionUtils.isEmpty(deleteUserIds)) {
                    boolean result = authingManagerDao.revokeResource(batchAuthInfo.getNamespaceCode(),
                            batchAuthInfo.getResource(), deleteUserIds);
                    if (result) {
                        LogUtil.createLogs(deleteUserIds.toString(), "delete", "permission",
                                "delete permissions", "localhost", "success");
                    } else {
                        LogUtil.createLogs(deleteUserIds.toString(), "delete", "permission",
                                "delete permissions", "localhost", "failed");
                    }
                }
            }
            List<String> addUserIds = new ArrayList<>();
            for (String userId : batchAuthInfo.getUserIds()) {
                if (!authUserIds.contains(userId)) {
                    addUserIds.add(userId);
                }
            }
            if (!CollectionUtils.isEmpty(addUserIds)) {
                String authActionPre = batchAuthInfo.getResource() + ":";
                List<String> authActions = batchAuthInfo.getActions().stream().map(x -> authActionPre + x)
                        .collect(Collectors.toList());
                AuthorizeInfo authorizeInfo = new AuthorizeInfo();
                authorizeInfo.setNamespace(batchAuthInfo.getNamespaceCode());
                AuthorizeInfo.AuthorizeData authorizeData = authorizeInfo.new AuthorizeData();
                authorizeData.setTargetType("USER");
                authorizeData.setTargetIdentifiers(addUserIds);
                AuthorizeInfo.AuthorizeResource authorizeResource = authorizeInfo.new AuthorizeResource();
                authorizeResource.setResourceType("DATA");
                authorizeResource.setCode(batchAuthInfo.getResource());
                authorizeResource.setActions(authActions);
                List<AuthorizeInfo.AuthorizeResource> resources = new ArrayList<>();
                resources.add(authorizeResource);
                authorizeData.setResources(resources);
                List<AuthorizeInfo.AuthorizeData> list = new ArrayList<>();
                list.add(authorizeData);
                authorizeInfo.setList(list);
                if (!authingManagerDao.authrizeResource(authorizeInfo)) {
                    LogUtil.createLogs(addUserIds.toString(), "auto add", "permission",
                            "set permissions", "localhost", "failed");
                    return false;
                }
            }
            if (!CollectionUtils.isEmpty(addUserIds)) {
                LogUtil.createLogs(addUserIds.toString(), "auto add", "permission",
                        "set permissions", "localhost", "success");
            }
            return true;
        } catch (Exception e) {
            LOGGER.error("batch authrize failed {}", e.getMessage());
            return true;
        }
    }
}
