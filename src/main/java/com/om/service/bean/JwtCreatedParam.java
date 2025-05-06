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

package com.om.service.bean;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtCreatedParam {
    /**
     * 初始化.
     *
     * @param appId 应用ID
     * @param userId 用户ID
     * @param username 用户名
     * @param permission 权限
     * @param inputPermission 输入权限
     * @param idToken id_token
     * @param oneidPrivacyVersionAccept 隐私签署
     * @param phoneExist 是否存在手机号
     */
    public JwtCreatedParam(String appId, String userId, String username, String permission, String inputPermission,
                           String idToken, String oneidPrivacyVersionAccept, Boolean phoneExist) {
        this.appId = appId;
        this.userId = userId;
        this.username = username;
        this.permission = permission;
        this.inputPermission = inputPermission;
        this.idToken = idToken;
        this.oneidPrivacyVersionAccept = oneidPrivacyVersionAccept;
        this.phoneExist = phoneExist;
    }

    /**
     * 应用ID.
     */
    private String appId;

    /**
     * 用户ID.
     */
    private String userId;

    /**
     * 用户名.
     */
    private String username;

    /**
     * 权限.
     */
    private String permission;

    /**
     * 输入权限.
     */
    private String inputPermission;

    /**
     * id_token.
     */
    private String idToken;

    /**
     * 隐私版本.
     */
    private String oneidPrivacyVersionAccept;

    /**
     * 手机号是否存在.
     */
    private Boolean phoneExist;
}
