package com.om.Vo;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class ManagementLog implements Serializable {

    private static final long serialVersionUID = 1L;

    private String type;

    private String time;

    private String func;

    private String eventDetails;

    private String requestUrl;

    private String method;

    private String appIP;

    private int status;

    private String message;

    private String ErrorLog;

    private String operator;
    
}
