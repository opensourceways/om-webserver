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

package com.om.controller.bean.request;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class BatchAuthInfo {
    /**
     * 权限空间code.
     */
    private String namespaceCode;

    /**
     * 资源路径.
     */
    private String resource;

    /**
     * 用户ID.
     */
    private List<String> userIds;

    /**
     * 资源权限操作.
     */
    private List<String> actions;

    /**
     * 是否删除其他用于的权限.
     */
    private Boolean isDeleteOthers;
}
