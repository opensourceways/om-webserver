package com.om.Vo;

import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
public class ManagementLog implements Serializable {
    /**
     * 序列化版本UID.
     */
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 类型.
     */
    private String type;

    /**
     * 时间.
     */
    private String time;

    /**
     * 功能.
     */
    private String func;

    /**
     * 事件详情.
     */
    private String eventDetails;

    /**
     * 请求URL.
     */
    private String requestUrl;

    /**
     * 方法.
     */
    private String method;

    /**
     * 应用IP.
     */
    private String appIP;

    /**
     * 状态码.
     */
    private int status;

    /**
     * 消息.
     */
    private String message;

    /**
     * 错误日志.
     */
    private String errorLog;

    /**
     * 操作人.
     */
    private String operator;
}
