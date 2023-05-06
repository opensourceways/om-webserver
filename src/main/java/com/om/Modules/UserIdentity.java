package com.om.Modules;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class UserIdentity {
    private Object userIdInIdp;
    private Object provider;
    private Object username;
    private Object nickname;
    private Object photo;
    private Object email;
    private Object phone;
    private Object blog;
    private Object weibo;
    private Object wechat;
    private Object qq;
    private Object accessToken;
}
