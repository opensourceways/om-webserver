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

@Getter
@Setter
public class OidcAuthParam {
    /**
     * token.
     */
    private String token;

    /**
     * 应用ID.
     */
    private String appId;

    /**
     * 重定向地址.
     */
    private String redirectUri;

    /**
     * 响应类型.
     */
    private String responseType;

    /**
     * state.
     */
    private String state;

    /**
     * scope.
     */
    private String scope;

    /**
     * nonce.
     */
    private String nonce;

    /**
     * 初始化.
     */
    public OidcAuthParam() {

    }

    /**
     * 初始化.
     *
     * @param token token
     * @param appId 应用ID
     * @param redirectUri 回调地址
     * @param responseType 相应类型
     * @param state state
     * @param scope scope
     * @param nonce nonce
     */
    public OidcAuthParam(String token, String appId, String redirectUri, String responseType,
                         String state, String scope, String nonce) {
        this.token = token;
        this.appId = appId;
        this.redirectUri = redirectUri;
        this.responseType = responseType;
        this.state = state;
        this.scope = scope;
        this.nonce = nonce;
    }
}
