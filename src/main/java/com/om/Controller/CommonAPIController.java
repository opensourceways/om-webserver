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

package com.om.Controller;

import com.alibaba.fastjson2.JSON;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;

/**
 * CommonAPIController 通用 API 控制器，处理通用的 API 端点和功能.
 */
@RequestMapping(value = "/oneid")
@RestController
public class CommonAPIController {
    /**
     * OneID隐私版本.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

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

    /**
     * 获取当前隐私协议版本.
     *
     * @return 隐私协议版本信息
     */
    @RequestMapping(value = "/privacy/version", method = RequestMethod.GET)
    public ResponseEntity getPrivacyVersion() {
        HashMap<String, Object> userData = new HashMap<>();
        userData.put("oneidPrivacyAccepted", oneidPrivacyVersion);
        return result(HttpStatus.OK, "success", userData);
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(
                        HtmlUtils.htmlUnescape(JSON.toJSONString(res)), HashMap.class), status);
        return responseEntity;
    }
}
