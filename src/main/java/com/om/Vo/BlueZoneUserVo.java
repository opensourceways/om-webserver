package com.om.Vo;

import com.om.Modules.BlueZoneUser;

import java.util.List;

public class BlueZoneUserVo {
    private String token;
    private List<BlueZoneUser> users;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public List<BlueZoneUser> getUsers() {
        return users;
    }

    public void setUsers(List<BlueZoneUser> users) {
        this.users = users;
    }
}
