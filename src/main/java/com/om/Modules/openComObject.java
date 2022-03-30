package com.om.Modules;

import org.springframework.stereotype.Repository;

import java.util.Calendar;
import java.util.Date;

/**
 * @author zhxia
 * @date 2020/11/5 16:36
 */
@Repository
public class openComObject {
    protected String extOs_index;
    protected String extOs_queryStr;
    protected String businessOsv_index;
    protected String businessOsv_queryStr;
    protected String sigs_index;
    protected String sigs_queryStr;
    protected String users_index;
    protected String users_queryStr;
    protected String contributors_index;
    protected String contributors_queryStr;
    protected String noticeusers_index;
    protected String noticeusers_queryStr;
    protected String communitymembers_index;
    protected String communitymembers_queryStr;
    protected String GiteeAllIndex;
    protected String GiteeAll_qIssueStrBymil;
    protected String GiteeAllQueryAllstr;
    protected String GiteeStarCountQueryStr;
    protected String GiteeIssueCountQueryStr;
    protected String GiteePrCountQueryStr;
    protected String GiteeAggCompanyQueryStr;
    protected String GiteeAggUserQueryStr;
    protected String GiteeContributesQueryStr;
    protected String DownloadQueryIndex;
    protected String DownloadQueryStr;
    protected String DownloadDockerHubQueryStr;
    protected String BlueZoneContributesIndex;
    protected String BlueZoneUsersIndex;
    protected String star_fork_index;
    protected String star_fork_queryStr;
    protected String tokenUserName;
    protected String tokenUserPassword;
    protected String tokenBasePassword;
    protected String tokenExpireSeconds;
    protected String cveDetailsQueryIndex;
    protected String durationAggIndex;
    protected String durationAggQueryStr;
    protected String bug_questionnaire_index;
    protected String bug_questionnaire_queryAllStr;
    protected String obsDetailsIndex;
    protected String obsDetailsIndexQueryStr;
    protected String obsPackageQueryStr;
    protected String isoBuildIndex;
    protected String isoBuildIndexQueryStr;
    protected String sigDetailsIndex;
    protected String sigDetailsIndexQueryStr;
    protected String claCorporationIndex;
    protected String issueScoreIndex;
    protected String issueScoreQueryStr;

    public String getIssueScoreIndex() {
        return issueScoreIndex;
    }

    public void setIssueScoreIndex(String issueScoreIndex) {
        this.issueScoreIndex = issueScoreIndex;
    }

    public String getIssueScoreQueryStr() {
        return issueScoreQueryStr;
    }

    public void setIssueScoreQueryStr(String issueScoreQueryStr) {
        this.issueScoreQueryStr = issueScoreQueryStr;
    }


    public String getGiteeContributesQueryStr() {
        return GiteeContributesQueryStr;
    }

    public void setGiteeContributesQueryStr(String giteeContributesQueryStr) {
        GiteeContributesQueryStr = giteeContributesQueryStr;
    }

    public String getClaCorporationIndex() {
        return claCorporationIndex;
    }

    public void setClaCorporationIndex(String claCorporationIndex) {
        this.claCorporationIndex = claCorporationIndex;
    }

    public String getGiteeAggCompanyQueryStr() {
        return GiteeAggCompanyQueryStr;
    }

    public void setGiteeAggCompanyQueryStr(String giteeAggCompanyQueryStr) {
        GiteeAggCompanyQueryStr = giteeAggCompanyQueryStr;
    }

    public String getGiteeAggUserQueryStr() {
        return GiteeAggUserQueryStr;
    }

    public void setGiteeAggUserQueryStr(String giteeAggUserQueryStr) {
        GiteeAggUserQueryStr = giteeAggUserQueryStr;
    }

    public String getObsPackageQueryStr() {
        return obsPackageQueryStr;
    }

    public void setObsPackageQueryStr(String obsPackageQueryStr) {
        this.obsPackageQueryStr = obsPackageQueryStr;
    }

    public String getObsDetailsIndex() {
        return obsDetailsIndex;
    }

    public void setObsDetailsIndex(String obsDetailsIndex) {
        this.obsDetailsIndex = obsDetailsIndex;
    }

    public String getObsDetailsIndexQueryStr() {
        return obsDetailsIndexQueryStr;
    }

    public void setObsDetailsIndexQueryStr(String obsDetailsIndexQueryStr) {
        this.obsDetailsIndexQueryStr = obsDetailsIndexQueryStr;
    }

    public String getIsoBuildIndex() {
        return isoBuildIndex;
    }

    public void setIsoBuildIndex(String isoBuildIndex) {
        this.isoBuildIndex = isoBuildIndex;
    }

    public String getIsoBuildIndexQueryStr() {
        return isoBuildIndexQueryStr;
    }

    public void setIsoBuildIndexQueryStr(String isoBuildIndexQueryStr) {
        this.isoBuildIndexQueryStr = isoBuildIndexQueryStr;
    }

    public String getSigDetailsIndex() {
        return sigDetailsIndex;
    }

    public void setSigDetailsIndex(String sigDetailsIndex) {
        this.sigDetailsIndex = sigDetailsIndex;
    }

    public String getSigDetailsIndexQueryStr() {
        return sigDetailsIndexQueryStr;
    }

    public void setSigDetailsIndexQueryStr(String sigDetailsIndexQueryStr) {
        this.sigDetailsIndexQueryStr = sigDetailsIndexQueryStr;
    }

    public String getBug_questionnaire_index() {
        return bug_questionnaire_index;
    }

    public void setBug_questionnaire_index(String bug_questionnaire_index) {
        this.bug_questionnaire_index = bug_questionnaire_index;
    }


    public String getDurationAggIndex() {
        return durationAggIndex;
    }

    public void setDurationAggIndex(String durationAggIndex) {
        this.durationAggIndex = durationAggIndex;
    }

    public String getDurationAggQueryStr() {
        return durationAggQueryStr;
    }

    public void setDurationAggQueryStr(String durationAggQueryStr) {
        this.durationAggQueryStr = durationAggQueryStr;
    }

    public String getCveDetailsQueryIndex() {
        return cveDetailsQueryIndex;
    }

    public void setCveDetailsQueryIndex(String cveDetailsQueryIndex) {
        this.cveDetailsQueryIndex = cveDetailsQueryIndex;
    }

    public String getTokenUserName() {
        return tokenUserName;
    }

    public void setTokenUserName(String tokenUserName) {
        this.tokenUserName = tokenUserName;
    }

    public String getTokenUserPassword() {
        return tokenUserPassword;
    }

    public void setTokenUserPassword(String tokenUserPassword) {
        this.tokenUserPassword = tokenUserPassword;
    }

    public String getTokenBasePassword() {
        return tokenBasePassword;
    }

    public void setTokenBasePassword(String tokenBasePassword) {
        this.tokenBasePassword = tokenBasePassword;
    }

    public String getTokenExpireSeconds() {
        return tokenExpireSeconds;
    }

    public void setTokenExpireSeconds(String tokenExpireSeconds) {
        this.tokenExpireSeconds = tokenExpireSeconds;
    }

    public String getStar_fork_index() {
        return star_fork_index;
    }

    public void setStar_fork_index(String star_fork_index) {
        this.star_fork_index = star_fork_index;
    }

    public String getStar_fork_queryStr() {
        return star_fork_queryStr;
    }

    public void setStar_fork_queryStr(String star_fork_queryStr) {
        this.star_fork_queryStr = star_fork_queryStr;
    }

    public String getBlueZoneUsersIndex() {
        return BlueZoneUsersIndex;
    }

    public void setBlueZoneUsersIndex(String blueZoneUsersIndex) {
        BlueZoneUsersIndex = blueZoneUsersIndex;
    }

    public String getBlueZoneContributesIndex() {
        return BlueZoneContributesIndex;
    }

    public void setBlueZoneContributesIndex(String blueZoneContributesIndex) {
        BlueZoneContributesIndex = blueZoneContributesIndex;
    }

    public String getDownloadDockerHubQueryStr() {
        return DownloadDockerHubQueryStr;
    }

    public void setDownloadDockerHubQueryStr(String downloadDockerHubQueryStr) {
        DownloadDockerHubQueryStr = downloadDockerHubQueryStr;
    }

    public String getDownloadQueryIndex() {
        return DownloadQueryIndex;
    }

    public void setDownloadQueryIndex(String downloadQueryIndex) {
        DownloadQueryIndex = downloadQueryIndex;
    }

    public String getDownloadQueryStr() {
        return DownloadQueryStr;
    }

    public void setDownloadQueryStr(String downloadQueryStr) {
        DownloadQueryStr = downloadQueryStr;
    }

    public String getGiteeStarCountQueryStr() {
        return GiteeStarCountQueryStr;
    }

    public void setGiteeStarCountQueryStr(String giteeStarCountQueryStr) {
        GiteeStarCountQueryStr = giteeStarCountQueryStr;
    }

    public String getGiteeIssueCountQueryStr() {
        return GiteeIssueCountQueryStr;
    }

    public void setGiteeIssueCountQueryStr(String giteeIssueCountQueryStr) {
        GiteeIssueCountQueryStr = giteeIssueCountQueryStr;
    }

    public String getGiteePrCountQueryStr() {
        return GiteePrCountQueryStr;
    }

    public void setGiteePrCountQueryStr(String giteePrCountQueryStr) {
        GiteePrCountQueryStr = giteePrCountQueryStr;
    }

    public String getGiteeAllQueryAllstr() {
        return GiteeAllQueryAllstr;
    }

    public void setGiteeAllQueryAllstr(String giteeAllQueryAllstr) {
        GiteeAllQueryAllstr = giteeAllQueryAllstr;
    }

    public String getGiteeAll_qIssueStrBymil() {
        return GiteeAll_qIssueStrBymil;
    }

    public void setGiteeAll_qIssueStrBymil(String giteeAll_qIssueStrBymil) {
        GiteeAll_qIssueStrBymil = giteeAll_qIssueStrBymil;
    }

    public String getGiteeAllIndex() {
        return GiteeAllIndex;
    }

    public void setGiteeAllIndex(String giteeAllIndex) {
        GiteeAllIndex = giteeAllIndex;
    }

    public String getExtOs_index() {
        return extOs_index;
    }

    public void setExtOs_index(String extOs_index) {
        this.extOs_index = extOs_index;
    }

    public String getExtOs_queryStr() {
        return extOs_queryStr;
    }

    public void setExtOs_queryStr(String extOs_queryStr) {
        this.extOs_queryStr = extOs_queryStr;
    }

    public String getSigs_index() {
        return sigs_index;
    }

    public void setSigs_index(String sigs_index) {
        this.sigs_index = sigs_index;
    }

    public String getSigs_queryStr() {
        return sigs_queryStr;
    }

    public void setSigs_queryStr(String sigs_queryStr) {
        this.sigs_queryStr = sigs_queryStr;
    }

    public String getUsers_index() {
        return users_index;
    }

    public void setUsers_index(String users_index) {
        this.users_index = users_index;
    }

    public String getUsers_queryStr() {
        return users_queryStr;
    }

    public void setUsers_queryStr(String users_queryStr) {
        this.users_queryStr = users_queryStr;
    }

    public String getContributors_index() {
        return contributors_index;
    }

    public void setContributors_index(String contributors_index) {
        this.contributors_index = contributors_index;
    }

    public String getContributors_queryStr() {
        return contributors_queryStr;
    }

    public void setContributors_queryStr(String contributors_queryStr) {
        this.contributors_queryStr = contributors_queryStr;
    }

    public String getNoticeusers_index() {
        return noticeusers_index;
    }

    public void setNoticeusers_index(String noticeusers_index) {
        this.noticeusers_index = noticeusers_index;
    }

    public String getNoticeusers_queryStr() {
        return noticeusers_queryStr;
    }

    public void setNoticeusers_queryStr(String noticeusers_queryStr) {
        this.noticeusers_queryStr = noticeusers_queryStr;
    }

    public String getBusinessOsv_index() {
        return businessOsv_index;
    }

    public void setBusinessOsv_index(String businessOsv_index) {
        this.businessOsv_index = businessOsv_index;
    }

    public String getBusinessOsv_queryStr() {
        return businessOsv_queryStr;
    }

    public void setBusinessOsv_queryStr(String businessOsv_queryStr) {
        this.businessOsv_queryStr = businessOsv_queryStr;
    }

    public String getCommunitymembers_index() {
        return communitymembers_index;
    }

    public void setCommunitymembers_index(String communitymembers_index) {
        this.communitymembers_index = communitymembers_index;
    }

    public String getCommunitymembers_queryStr() {
        return communitymembers_queryStr;
    }

    public void setCommunitymembers_queryStr(String communitymembers_queryStr) {
        this.communitymembers_queryStr = communitymembers_queryStr;
    }

    public String getBug_questionnaire_queryAllStr() {
        return bug_questionnaire_queryAllStr;
    }

    public void setBug_questionnaire_queryAllStr(String bug_questionnaire_queryAllStr) {
        this.bug_questionnaire_queryAllStr = bug_questionnaire_queryAllStr;
    }

    public String getCountQueryStr(String item) {
        String queryStr = "";
        switch (item) {
            case "stars":
                queryStr = getGiteeStarCountQueryStr();
                break;
            case "issues":
                queryStr = getGiteeIssueCountQueryStr();
                break;
            case "prs":
                queryStr = getGiteePrCountQueryStr();
                break;
            default:
                return "";
        }

        return queryStr;
    }

    public String getAggCountQueryStr(String groupField, String contributeType, String timeRange, String community) {
        String queryStr;
        String queryJson;
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);

        if (groupField.equals("company")) {
            queryJson = getGiteeAggCompanyQueryStr();
        } else {
            queryJson = getGiteeAggUserQueryStr();
        }

        switch (contributeType.toLowerCase()) {
            case "pr":
                if (community.toLowerCase().equals("opengauss")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_gitee_pull_request");
                } else {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_pull_state_merged");
                }
                break;
            case "issue":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_gitee_issue");
                break;
            case "comment":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_gitee_comment");
                break;
            default:
                return "";
        }

        return queryStr;
    }

    private long getPastTime(String timeRange) {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        switch (timeRange.toLowerCase()) {
            case "lastonemonth":
                c.add(Calendar.MONTH, -1);
                break;
            case "lasthalfyear":
                c.add(Calendar.MONTH, -6);
                break;
            case "lastoneyear":
                c.add(Calendar.YEAR, -1);
                break;
            default:
                c.setTimeInMillis(0);
        }
        return c.getTimeInMillis();
    }
}


