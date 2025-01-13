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

package com.om.dao.bean;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserInfo {
    /**
     * 用户ID.
     */
    private String userId;

    /**
     * 用户名.
     */
    private String username;

    /**
     * 用户三方绑定用户ID.
     */
    private String userIdInIdp;
}
