package com.om.Vo;

import java.util.List;

public class IsoBuildTimesVo {
    private String community;
    private List<String> branchs;
    private Integer limit;

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public List<String> getBranchs() {
        return branchs;
    }

    public void setBranchs(List<String> branchs) {
        this.branchs = branchs;
    }

    public Integer getLimit() {
        return limit;
    }

    public void setLimit(Integer limit) {
        this.limit = limit;
    }
}
