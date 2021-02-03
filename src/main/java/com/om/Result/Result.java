package com.om.Result;

import java.util.ArrayList;
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
}
