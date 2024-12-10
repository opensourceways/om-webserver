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

package com.om.Controller.bean.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NamespaceInfoPage {
    /**
     * 分页.
     */
    private Integer page;

    /**
     * 分页限制.
     */
    private Integer limit;

    /**
     * 命名空间code.
     */
    private String namespaceCode;
}
