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

package com.om.Controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * CommonAPIController 通用 API 控制器，处理通用的 API 端点和功能.
 */
@RequestMapping(value = "/oneid")
@RestController
public class CommonAPIController {
    /**
     * 表示服务正常状态的常量.
     */
    private static final String SERVICE_STATUS_NORMAL = "normal";

    /**
     * 检查 OM 服务的方法.
     *
     * @return SERVICE_STATUS_NORMAL
     */
    @RequestMapping(value = "/checkOmService", method = RequestMethod.GET)
    public String checkOmService() {
        return SERVICE_STATUS_NORMAL;
    }
}
