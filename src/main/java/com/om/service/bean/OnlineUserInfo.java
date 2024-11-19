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

package com.om.service.bean;

import java.util.Set;

/**
 * 登录用户在线的缓存信息.
 */
public class OnlineUserInfo {
    /**
     * id_token.
     */
    private String idToken;

    /**
     * 加入的应用的登出接口.
     */
    private Set<String> logoutUrls;

    /**
     * 获取id_token.
     *
     * @return id_token
     */
    public String getIdToken() {
        return idToken;
    }

    /**
     * 设置id_token.
     *
     * @param idToken id_token
     */
    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    /**
     * 获取logoutUrls.
     *
     * @return logoutUrls
     */
    public Set<String> getLogoutUrls() {
        return logoutUrls;
    }

    /**
     * 设置logoutUrls.
     *
     * @param logoutUrls logoutUrls
     */
    public void setLogoutUrls(Set<String> logoutUrls) {
        this.logoutUrls = logoutUrls;
    }
}
