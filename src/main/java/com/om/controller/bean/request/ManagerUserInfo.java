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

package com.om.controller.bean.request;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.util.Objects;
import java.util.stream.Stream;

/**
 * 用户信息查询.
 */
@Getter
@Setter
public class ManagerUserInfo {
    /**
     * 用户名称.
     */
    private String username;

    /**
     * 用户Id.
     */
    private String userId;

    /**
     * gitee Login.
     */
    private String giteeLogin;

    /**
     * github Login.
     */
    private String githubLogin;

    /**
     * 手机号码.
     */
    private String phone;

    /**
     * 邮箱.
     */
    private String email;

    /**
     * 只允许一个参数.
     * @return 是否只有1各参数.
     */
    public boolean checkSingle() {
        long count = Stream.of(this.username, this.userId, this.giteeLogin, this.githubLogin, this.phone, this.email)
                .filter(StringUtils::isNotBlank).count();
        return count == 1;
    }
}
