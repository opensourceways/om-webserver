package com.om.Vo.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ThirdPartyRegisterParam {
    String register_token;
    String app_id;
    String state;
}
