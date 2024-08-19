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

package com.om.result;

import com.alibaba.fastjson2.JSON;
import com.om.modules.MessageCodeConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Result: 表示操作结果的类.
 */
public class Result {
    /**
     * 获取数据列表.
     *
     * @return data集合
     */
    public List getData() {
        return data;
    }

    /**
     * 设置数据并返回结果对象.
     *
     * @param data 要设置的数据列表
     * @return Result 对象本身
     */
    public Result setData(List data) {
        this.data = data;
        return this;
    }

    /**
     * 返回数据.
     **/
    private List data;
    /**
     * 状态码.
     **/
    private int code;
    /**
     * 返回信息描述.
     **/
    private String message;
    /**
     * data总条数.
     **/
    private int total;

    /**
     * 获取结果代码.
     *
     * @return 结果代码
     */
    public int getCode() {
        return code;
    }

    /**
     * 设置结果代码并返回结果对象.
     *
     * @param code 结果代码
     * @return Result 对象本身
     */
    public Result setCode(int code) {
        this.code = code;
        return this;
    }

    /**
     * 获取消息内容.
     *
     * @return 消息内容
     */
    public String getMessage() {
        return message;
    }

    /**
     * 设置消息内容并返回结果对象.
     *
     * @param message 消息内容
     * @return Result 对象本身
     */
    public Result setMessage(String message) {
        this.message = message;
        return this;
    }

    /**
     * 获取总数.
     *
     * @return 总数
     */
    public int getTotal() {
        return total;
    }

    /**
     * 设置总数并返回结果对象.
     *
     * @param total 总数
     * @return Result 对象本身
     */
    public Result setTotal(int total) {
        this.total = total;
        return this;
    }

    /**
     * 设置响应实体，包括HTTP状态、消息代码配置、消息内容、数据和错误码映射.
     *
     * @param status     HTTP状态
     * @param msgCode    消息代码配置
     * @param msg        消息内容
     * @param data       数据
     * @param error2code 错误码映射
     * @return ResponseEntity 响应实体
     */
    public ResponseEntity setResult(HttpStatus status, MessageCodeConfig msgCode, String msg, Object data,
                                    Map<String, MessageCodeConfig> error2code) {
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
        ResponseEntity<HashMap<String, Object>> responseEntity =
                new ResponseEntity<>(JSON.parseObject(HtmlUtils.htmlUnescape(JSON.toJSONString(res)),
                        HashMap.class), status);
        return responseEntity;
    }
}
