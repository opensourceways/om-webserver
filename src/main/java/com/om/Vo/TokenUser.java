package com.om.Vo;

public class TokenUser {
    private String community;
    private String username;
    private String password;

    public TokenUser(String community, String username, String password) {
        this.community = community;
        this.username = username;
        this.password = password;
    }

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
