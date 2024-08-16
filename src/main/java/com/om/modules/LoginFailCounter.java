/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.modules;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * 登录失败计数器类.
 */
@Data
@Accessors(chain = true)
public class LoginFailCounter {
    /**
     * 账号信息.
     */
    private String account;

    /**
     * IP地址.
     */
    private String ip;

    /**
     * 账号键.
     */
    private String accountKey;

    /**
     * IP键.
     */
    private String ipKey;

    /**
     * 账号计数.
     */
    private int accountCount;

    /**
     * IP计数.
     */
    private int ipCount;

    /**
     * 限制计数.
     */
    private int limitCount;

    /**
     * 限制秒数.
     */
    private long limitSeconds;
}
