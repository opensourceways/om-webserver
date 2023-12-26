package com.om.Vo.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginParam {
    private String community;
    private String client_id;
    private String code;
    private String account;
    private String password;

    private String captchaVerification;
}
