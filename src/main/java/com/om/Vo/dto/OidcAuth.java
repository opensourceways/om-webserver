package com.om.Vo.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OidcAuth {
    private String client_id;
    private String response_type;
    private String redirect_uri;
    private String scope;
    private String state;
}
