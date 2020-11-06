package com.huawei.Modules;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

/**
 * @author zhxia
 * @date 2020/11/5 15:43
 */
@Repository
public class openLookeng extends openComObject {


    @Value("${openLookeng.access.token}")
    String access_token;
    public String getAccess_token() {
        return access_token;
    }

    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }
}
