package com.om.Vo;

import java.util.List;

public class BlueZoneContributeVo {
    private String token;
    private String startTime;
    private String endTime;
    private List<String> gitee_id;
    private List<String> github_id;

    public List<String> getGitee_id() {
        return gitee_id;
    }

    public void setGitee_id(List<String> gitee_id) {
        this.gitee_id = gitee_id;
    }

    public List<String> getGithub_id() {
        return github_id;
    }

    public void setGithub_id(List<String> github_id) {
        this.github_id = github_id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getStartTime() {
        return startTime;
    }

    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }

    public String getEndTime() {
        return endTime;
    }

    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }
}
