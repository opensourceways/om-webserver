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

import java.util.List;

@Setter
@Getter
public class AuthorizeInfo {
    /**
     * 命名空间.
     */
    private String namespace;

    /**
     * 权限数据.
     */
    private List<AuthorizeData> list;

    @Setter
    @Getter
    public class AuthorizeData {
        /**
         * 数据类型,比如USER.
         */
        private String targetType;

        /**
         * 用户ID.
         */
        private List<String> targetIdentifiers;

        /**
         * 资源.
         */
        private List<AuthorizeResource> resources;
    }

    @Setter
    @Getter
    public class AuthorizeResource {
        /**
         * 资源code.
         */
        private String code;

        /**
         * 资源类型.
         */
        private String resourceType;

        /**
         * 操作权限.
         */
        private List<String> actions;
    }
}
