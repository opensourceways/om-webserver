package com.om.Modules;

public class BlueZoneUser {
    private String name;
    private String org;
    private String gitee_id;
    private String github_id;
    private String email;

    public String getGitee_id() {
        return gitee_id;
    }

    public void setGitee_id(String gitee_id) {
        this.gitee_id = gitee_id;
    }

    public String getGithub_id() {
        return github_id;
    }

    public void setGithub_id(String github_id) {
        this.github_id = github_id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getOrg() {
        return org;
    }

    public void setOrg(String org) {
        this.org = org;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
