package com.om.Vo;

import java.util.ArrayList;

public class BugQuestionnaireVo {

    private String bugDocFragment;
    private ArrayList<String> existProblem = new ArrayList<>();
    private Integer comprehensiveSatisfication;
    private String participateReason;
    private String email;
    private String fillTime;

    public ArrayList<String> getExistProblem() {
        return existProblem;
    }

    public void setExistProblem(ArrayList<String> existProblem) {
        this.existProblem = existProblem;
    }

    public String getBugDocFragment() {
        return bugDocFragment;
    }

    public void setBugDocFragment(String bugDocFragment) {
        this.bugDocFragment = bugDocFragment;
    }

    public Integer getComprehensiveSatisfication() {
        return comprehensiveSatisfication;
    }

    public void setComprehensiveSatisfication(Integer comprehensiveSatisfication) {
        this.comprehensiveSatisfication = comprehensiveSatisfication;
    }

    public String getParticipateReason() {
        return participateReason;
    }

    public void setParticipateReason(String participateReason) {
        this.participateReason = participateReason;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFillTime() {
        return fillTime;
    }

    public void setFillTime(String fillTime) {
        this.fillTime = fillTime;
    }


}
