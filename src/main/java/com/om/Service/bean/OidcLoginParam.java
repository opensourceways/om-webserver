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

package com.om.Service.bean;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class OidcLoginParam {
    /**
     * 应用ID.
     */
    private String appId;

    /**
     * 应用秘钥.
     */
    private String appSecret;

    /**
     * 用户名.
     */
    private String account;

    /**
     * 密码.
     */
    private String password;

    /**
     * 回调地址.
     */
    private String redirectUri;

    /**
     * scope.
     */
    private String scope;

    /**
     * 用户IP.
     */
    private String clientIp;

    /**
     * 构造体.
     *
     * @param appId appId
     * @param appSecret appSecret
     * @param account account
     * @param password password
     * @param redirectUri redirectUri
     * @param scope scope
     * @param clientIp clientIp
     */
    public OidcLoginParam(String appId, String appSecret, String account,
                          String password, String redirectUri, String scope, String clientIp) {
        this.appId = appId;
        this.appSecret = appSecret;
        this.account = account;
        this.password = password;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.clientIp = clientIp;
    }
}
