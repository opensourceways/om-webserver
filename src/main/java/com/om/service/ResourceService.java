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

package com.om.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.om.modules.MessageCodeConfig;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.om.controller.bean.request.NamespaceInfoPage;
import com.om.controller.bean.request.PermissionInfo;
import com.om.controller.bean.request.ResourceInfo;
import com.om.controller.bean.response.UserOfResourceInfo;
import com.om.dao.AuthingManagerDao;

@Service
public class ResourceService {
    /**
     * 注入authingservice.
     */
    @Autowired
    private AuthingService authingService;

    /**
     * Authing的管理面接口.
     */
    @Autowired
    private AuthingManagerDao authingManagerDao;

    /**
     * 查询是否具备权限.
     *
     * @param permissionInfo 权限实例
     * @return 是否具备权限的结果
     */
    public ResponseEntity checkPermission(PermissionInfo permissionInfo) {
        HashMap<String, Boolean> hasPermission = new HashMap<>();
        hasPermission.put("hasPermission", false);
        if (StringUtils.isAnyBlank(permissionInfo.getResource(),
                permissionInfo.getUserId(), permissionInfo.getNamespaceCode())) {
            return authingService.result(HttpStatus.OK, "success", hasPermission);
        }
        String resource = authingManagerDao.convertResource(permissionInfo.getResource());
        if (CollectionUtils.isEmpty(permissionInfo.getActions())) {
            return authingService.result(HttpStatus.OK, "success", hasPermission);
        }
        ArrayList<String> pers = authingManagerDao.getUserPermission(permissionInfo.getUserId(),
                permissionInfo.getNamespaceCode());
        List<String> perActions = new ArrayList<>();
        for (String per : pers) {
            String[] perList = per.split(":");
            if (perList.length > 1 && StringUtils.equals(resource, perList[0])) {
                perActions.add(perList[1]);
            }
        }
        if ("OR".equals(permissionInfo.getOperator())) {
            for (String action : perActions) {
                if (permissionInfo.getActions().contains(action)) {
                    hasPermission.put("hasPermission", true);
                    break;
                }
            }
            return authingService.result(HttpStatus.OK, "success", hasPermission);
        } else {
            for (String action : permissionInfo.getActions()) {
                if (!perActions.contains(action)) {
                    return authingService.result(HttpStatus.OK, "success", hasPermission);
                }
            }
            hasPermission.put("hasPermission", true);
            return authingService.result(HttpStatus.OK, "success", hasPermission);
        }
    }

    /**
     * 根据权限获取对应资源.
     *
     * @param permissionInfo 权限实例
     * @return 资源列表
     */
    public ResponseEntity getResources(PermissionInfo permissionInfo) {
        HashMap<String, Set<String>> perResourceMap = new HashMap<>();
        Set<String> resources = new HashSet<>();
        perResourceMap.put("resources", resources);
        if (StringUtils.isAnyBlank(permissionInfo.getUserId(), permissionInfo.getNamespaceCode())) {
            return authingService.result(HttpStatus.OK, "success", perResourceMap);
        }
        ArrayList<String> pers = authingManagerDao.getUserPermission(permissionInfo.getUserId(),
                permissionInfo.getNamespaceCode());
        HashMap<String, List<String>> authPermissionMap = new HashMap<>();
        for (String per : pers) {
            String[] perList = per.split(":");
            if (perList.length > 1) {
                String resource = perList[0];
                resource = authingManagerDao.convertResource2Outside(resource);
                authPermissionMap.putIfAbsent(resource, new ArrayList<>());
                authPermissionMap.get(resource).add(perList[1]);
            }
        }
        if (CollectionUtils.isEmpty(permissionInfo.getActions())) {
            resources.addAll(authPermissionMap.keySet());
        } else {
            for (String resource : authPermissionMap.keySet()) {
                if (authPermissionMap.get(resource).containsAll(permissionInfo.getActions())) {
                    resources.add(resource);
                }
            }
        }
        return authingService.result(HttpStatus.OK, "success", perResourceMap);
    }

    /**
     * 获取权限空间下所有资源.
     *
     * @param namespaceInfoPage 分页查询
     * @return 资源数据
     */
    public ResponseEntity getAllResources(NamespaceInfoPage namespaceInfoPage) {
        String nameSpaceCode = namespaceInfoPage.getNamespaceCode();
        Integer page = namespaceInfoPage.getPage();
        Integer limit = namespaceInfoPage.getLimit();
        if (StringUtils.isBlank(nameSpaceCode) || (page != null && page < 1)
                || (limit != null && (limit < 1 || limit > 50))) {
            return authingService.result(HttpStatus.OK, "unrecognized param", Collections.emptyList());
        }
        HashMap<String, Object> resourceCodeMap = authingManagerDao.queryResources(namespaceInfoPage);
        return authingService.result(HttpStatus.OK, "success", resourceCodeMap);
    }

    /**
     * 获取资源下用户权限.
     *
     * @param resourceInfo 资源参数
     * @return 用户权限列表
     */
    public ResponseEntity listUserOfResource(ResourceInfo resourceInfo) {
        String nameSpaceCode = resourceInfo.getNamespaceCode();
        String resource = resourceInfo.getResource();
        if (StringUtils.isBlank(nameSpaceCode) || StringUtils.isBlank(resource)) {
            return authingService.result(HttpStatus.OK, "unrecognized param", Collections.emptyList());
        }
        List<UserOfResourceInfo> userList = authingManagerDao.listUserOfResource(nameSpaceCode, resource);
        if (userList == null) {
            return authingService.result(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012, null, null);
        }
        return authingService.result(HttpStatus.OK, "success", Map.of("users", userList));
    }
}
