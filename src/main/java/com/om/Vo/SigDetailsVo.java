package com.om.Vo;

import java.util.List;

public class SigDetailsVo {
    private String community;
    private List<String> sigs;

    public String getCommunity() {
        return community;
    }

    public void setCommunity(String community) {
        this.community = community;
    }

    public List<String> getSigs() {
        return sigs;
    }

    public void setSigs(List<String> sigs) {
        this.sigs = sigs;
    }
}
