/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Result;

import com.alibaba.fastjson2.JSON;
import com.om.Modules.MessageCodeConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author xiazhonghai
 * @date 2021/2/1 17:40
 * @description:
 */
public class Result {
    public List getData() {
        return data;
    }

    public Result setData(List data) {
        this.data = data;
        return this;
    }

    /**返回数据**/
    List data;
    /**状态码**/
    int code;
    /**返回信息描述**/
    String message;
    /**data总条数**/
    int total;



    public int getCode() {
        return code;
    }

    public Result setCode(int code) {
        this.code = code;
        return this;
    }

    public String getMessage() {
        return message;
    }

    public Result setMessage(String message) {
        this.message = message;
        return this;
    }

    public int getTotal() {
        return total;
    }

    public Result setTotal(int total) {
        this.total = total;
        return this;
    }

    public ResponseEntity setResult(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data, Map<String, MessageCodeConfig> error2code) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);

        if (status.value() == 400 && msgCode == null) {
            for (Map.Entry<String, MessageCodeConfig> entry : error2code.entrySet()) {
                if (msg.contains(entry.getKey())) {
                    msgCode = entry.getValue();
                    break;
                }
            }
        }

        if (msgCode != null) {
            HashMap<String, Object> msgMap = new HashMap<>();
            msgMap.put("code", msgCode.getCode());
            msgMap.put("message_en", msgCode.getMsgEn());
            msgMap.put("message_zh", msgCode.getMsgZh());
            res.put("msg", msgMap);
        }
        ResponseEntity<String> responseEntity = new ResponseEntity<>(HtmlUtils.htmlEscape(JSON.toJSONString(res)), status);
        return responseEntity;
    }
}
