package com.om.Vo;

import lombok.Data;

@Data
public class OauthTokenVo {
    /**
     * 应用ID.
     */
    private String appId;

    /**
     * 应用密钥.
     */
    private String appSecret;

}
