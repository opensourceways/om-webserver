package com.om.Vo;

/**
 * @author xiazhonghai
 * @date 2021/2/3 13:17
 * @description:
 */
public class ContributionResultVo {
    Double ranking;
    String name;
    String origanization;
    Double pr;
    Double issue;
    Double comments;

    public Double getRanking() {
        return ranking;
    }

    public void setRanking(Double ranking) {
        this.ranking = ranking;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getOriganization() {
        return origanization;
    }

    public void setOriganization(String origanization) {
        this.origanization = origanization;
    }

    public Double getPr() {
        return pr;
    }

    public void setPr(Double pr) {
        this.pr = pr;
    }

    public Double getIssue() {
        return issue;
    }

    public void setIssue(Double issue) {
        this.issue = issue;
    }

    public Double getComments() {
        return comments;
    }

    public void setComments(Double comments) {
        this.comments = comments;
    }
}
