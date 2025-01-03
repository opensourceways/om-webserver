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
package com.om.controller.bean.response;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
@Setter
@Getter
public class IdentityInfo {
    /**
     * 三方平台账号名.
     */
    @JsonProperty("loginName")
    private String loginName;
    /**
     * 用户名.
     */
    @JsonProperty("userId")
    private String userId;
    /**
     * 三方平台名.
     */
    @JsonProperty("thirdPlatform")
    private String thirdPlatform;
}
