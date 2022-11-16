package com.om.Modules;

import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

/**
 * @author zhxia
 * @date 2020/11/5 16:36
 */
@Repository
public class openComObject {
    protected String userTagIndex;
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
    protected String buildCheckResultIndex;
    protected String buildCheckMistakeIndex;
    protected String sig_name_queryStr;
    protected String sig_repo_queryStr;
    protected String meetings_index;
    protected String company_user_queryStr;
    protected String company_sigs_queryStr;
    protected String company_contribute_queryStr;
    protected String company_meetings_queryStr;
    protected String company_maintainers_queryStr;
    protected String sig_owner_type;
    protected String sig_agg_user_queryStr;
    protected String company_agg_user_queryStr;
    protected String all_sigs_owner_type;
    protected String sigs_feature_url;
    protected String company_users;
    protected String communityRepoQueryStr;
    protected String sig_score_queryStr;
    protected String sig_score_index;
    protected String sig_radar_score_index;
    protected String Tracker_index;
    protected String AllCompanySigsQueryStr;
    protected String all_sig_score_queryStr;
    protected String sig_info_queryStr;
    protected String user_owns_sigs_Str;
    protected String tc_owner_url;
    protected String group_agg_sig_queryStr;
    protected String user_owner_type_queryStr;
    protected String UserListQueryStr;
    protected String SigRepoCommittersQueryStr;
    protected String all_user_owner_type_queryStr;
    protected String repo_info_index;
    protected String repo_info_QuerStr;
    protected String sig_label_queryStr;

    public String getsig_label_queryStr() {
        return sig_label_queryStr;
    }

    public void setsig_label_queryStr(String sig_label_queryStr) {
        this.sig_label_queryStr = sig_label_queryStr;
    }

    public String getrepo_info_index() {
        return repo_info_index;
    }

    public void setrepo_info_index(String repo_info_index) {
        this.repo_info_index = repo_info_index;
    }

    public String getrepo_info_QuerStr() {
        return repo_info_QuerStr;
    }

    public void setrepo_info_QuerStr(String repo_info_QuerStr) {
        this.repo_info_QuerStr = repo_info_QuerStr;
    }

    public String getall_user_owner_type_queryStr() {
        return all_user_owner_type_queryStr;
    }

    public void setall_user_owner_type_queryStr(String all_user_owner_type_queryStr) {
        this.all_user_owner_type_queryStr = all_user_owner_type_queryStr;
    }

    public String getSigRepoCommittersQueryStr() {
        return SigRepoCommittersQueryStr;
    }

    public void setSigRepoCommittersQueryStr(String SigRepoCommittersQueryStr) {
        this.SigRepoCommittersQueryStr = SigRepoCommittersQueryStr;
    }

    public String getUserTagIndex() {
        return userTagIndex;
    }

    public void setUserTagIndex(String userTagIndex) {
        this.userTagIndex = userTagIndex;
    }

    public String getUserListQueryStr() {
        return UserListQueryStr;
    }

    public void setUserListQueryStr(String UserListQueryStr) {
        this.UserListQueryStr = UserListQueryStr;
    }

    public String getuser_owner_type_queryStr() {
        return user_owner_type_queryStr;
    }

    public void setuser_owner_type_queryStr(String user_owner_type_queryStr) {
        this.user_owner_type_queryStr = user_owner_type_queryStr;
    }

    public String getgroup_agg_sig_queryStr() {
        return group_agg_sig_queryStr;
    }

    public void setgroup_agg_sig_queryStr(String group_agg_sig_queryStr) {
        this.group_agg_sig_queryStr = group_agg_sig_queryStr;
    }

    public String getuser_owns_sigs_Str() {
        return user_owns_sigs_Str;
    }

    public void setuser_owns_sigs_Str(String user_owns_sigs_Str) {
        this.user_owns_sigs_Str = user_owns_sigs_Str;
    }
 
    public String gettc_owner_url() {
        return tc_owner_url;
    }

    public void settc_owner_url(String tc_owner_url) {
        this.tc_owner_url = tc_owner_url;
    }

    public String getall_sig_score_queryStr() {
        return all_sig_score_queryStr;
    }

    public void setall_sig_score_queryStr(String all_sig_score_queryStr) {
        this.all_sig_score_queryStr = all_sig_score_queryStr;
    }

    public String getAllCompanySigsQueryStr() {
        return AllCompanySigsQueryStr;
    }

    public void setAllCompanySigsQueryStr(String AllCompanySigsQueryStr) {
        this.AllCompanySigsQueryStr = AllCompanySigsQueryStr;
    }

    public String getTracker_index() {
        return Tracker_index;
    }

    public void setTracker_index(String Tracker_index) {
        this.Tracker_index = Tracker_index;
    }

    public String getsig_score_queryStr() {
        return sig_score_queryStr;
    }

    public void setsig_score_queryStr(String sig_score_queryStr) {
        this.sig_score_queryStr = sig_score_queryStr;
    }

    public String getsig_score_index() {
        return sig_score_index;
    }

    public void setsig_score_index(String sig_score_index) {
        this.sig_score_index = sig_score_index;
    }

    public String getsig_radar_score_index() {
        return sig_radar_score_index;
    }

    public void setsig_radar_score_index(String sig_radar_score_index) {
        this.sig_radar_score_index = sig_radar_score_index;
    }

    public String getCommunityRepoQueryStr() {
        return communityRepoQueryStr;
    }

    public void setCommunityRepoQueryStr(String communityRepoQueryStr) {
        this.communityRepoQueryStr = communityRepoQueryStr;
    }

    public String getComapnyUsers() {
        return company_users;
    }

    public void setComapnyUsers(String company_users) {
        this.company_users = company_users;
    }

    public String getSigsFeature() {
        return sigs_feature_url;
    }

    public void setSigsFeature(String sigs_feature_url) {
        this.sigs_feature_url = sigs_feature_url;
    }

    public String getSigOwnerType() {
        return sig_owner_type;
    }

    public void setSigOwnerType(String sig_owner_type) {
        this.sig_owner_type = sig_owner_type;
    }

    public String getSigAggUserQueryStr() {
        return sig_agg_user_queryStr;
    }

    public void setSigAggUserQueryStr(String sig_agg_user_queryStr) {
        this.sig_agg_user_queryStr = sig_agg_user_queryStr;
    }

    public String getAllSigsOwnerType() {
        return all_sigs_owner_type;
    }

    public void setAllSigsOwnerType(String all_sigs_owner_type) {
        this.all_sigs_owner_type = all_sigs_owner_type;
    }

    public String getCompanyAggUserQueryStr() {
        return company_agg_user_queryStr;
    }

    public void setCompanyAggUserQueryStr(String company_agg_user_queryStr) {
        this.company_agg_user_queryStr = company_agg_user_queryStr;
    }

    public String getCompanyUserQueryStr() {
        return company_user_queryStr;
    }

    public void setCompanyUserQueryStr(String company_user_queryStr) {
        this.company_user_queryStr = company_user_queryStr;
    }

    public String getCompanySigsQueryStr() {
        return company_sigs_queryStr;
    }

    public void setCompanySigsQueryStr(String company_sigs_queryStr) {
        this.company_sigs_queryStr = company_sigs_queryStr;
    }

    public String getCompanyContributeQueryStr() {
        return company_contribute_queryStr;
    }

    public void setCompanyContributeQueryStr(String company_contribute_queryStr) {
        this.company_contribute_queryStr = company_contribute_queryStr;
    }

    public String getCompanyMeetingsQueryStr() {
        return company_meetings_queryStr;
    }

    public void setCompanyMeetingsQueryStr(String company_meetings_queryStr) {
        this.company_meetings_queryStr = company_meetings_queryStr;
    }

    public String getCompanyMaintainersQueryStr() {
        return company_maintainers_queryStr;
    }

    public void setCompanyMaintainersQueryStr(String company_maintainers_queryStr) {
        this.company_maintainers_queryStr = company_maintainers_queryStr;
    }

    public String getSigNameQueryStr() {
        return sig_name_queryStr;
    }

    public void setSigNameQueryStr(String sig_name_queryStr) {
        this.sig_name_queryStr = sig_name_queryStr;
    }

    public String getSigInfoQueryStr() {
        return sig_info_queryStr;
    }

    public void setSigInfoQueryStr(String sig_info_queryStr) {
        this.sig_info_queryStr = sig_info_queryStr;
    }

    public String getSigRepoQueryStr() {
        return sig_repo_queryStr;
    }

    public void setSigRepoQueryStr(String sig_repo_queryStr) {
        this.sig_repo_queryStr = sig_repo_queryStr;
    }

    public String getMeetingsIndex() {
        return meetings_index;
    }

    public void setMeetingsIndex(String meetings_index) {
        this.meetings_index = meetings_index;
    }

    public String getBuildCheckResultIndex() {
        return buildCheckResultIndex;
    }

    public void setBuildCheckResultIndex(String buildCheckResultIndex) {
        this.buildCheckResultIndex = buildCheckResultIndex;
    }

    public String getBuildCheckMistakeIndex() {
        return buildCheckMistakeIndex;
    }

    public void setBuildCheckMistakeIndex(String buildCheckMistakeIndex) {
        this.buildCheckMistakeIndex = buildCheckMistakeIndex;
    }

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

    public String getAggCountQueryStr(String groupField, String contributeType, String timeRange, String community, String repo, String sig) {
        String queryStr;
        String queryJson;
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);

        if (groupField.equals("company")) {
            queryJson = getGiteeAggCompanyQueryStr();
        } else {
            queryJson = getGiteeAggUserQueryStr();
        }
        repo = repo == null ? "*" : String.format("\\\"https://gitee.com/%s\\\"", repo);
        sig = sig == null ? "*" : sig;

        switch (contributeType.toLowerCase()) {
            case "pr":
                if (community.toLowerCase().equals("opengauss")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, repo, sig, "is_pull_state_merged");
                } else if (community.toLowerCase().equals("openeuler") && groupField.equals("company")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, sig, "is_pull_state_merged");
                } else {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_pull_state_merged");
                }
                break;
            case "issue":
                if (community.toLowerCase().equals("opengauss")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, repo, sig, "is_gitee_issue");
                } else if (community.toLowerCase().equals("openeuler") && groupField.equals("company")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, sig, "is_gitee_issue");
                } else {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_gitee_issue");
                }
                break;
            case "comment":
                if (community.toLowerCase().equals("opengauss")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, repo, sig, "is_gitee_comment");
                } else if (community.toLowerCase().equals("openeuler") && groupField.equals("company")) {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, sig, "is_gitee_comment");
                } else {
                    queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, "is_gitee_comment");
                }
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

    public String getAggSigRepoQueryStr(String sig) {
        String queryStr;
        String queryJson;
        queryJson = getSigRepoQueryStr();
        queryStr = String.format(queryJson, sig);
        return queryStr;
    }

    public String getAggCompanyUserQueryStr(String timeRange, String company) {
        String queryStr;
        String queryJson;
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);

        queryJson = getCompanyUserQueryStr();
        if (queryJson == null) {
            System.out.println("QueryStr is null...");
            return "";
        }
        queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, company);

        return queryStr;
    }

    public String[] getAggCompanyGiteeQueryStr(String queryJson, String timeRange, String company) {
        if (queryJson == null) {
            System.out.println("QueryStr is null...");
            return null;
        }
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);
        String[] queryJsons = queryJson.split(";");
        String[] queryStr = new String[queryJsons.length];
        for (int i = 0; i < queryJsons.length; i++) {
            queryStr[i] = String.format(queryJsons[i], lastTimeMillis, currentTimeMillis, company);
        }
        return queryStr;
    }

    public String getAggGroupCountQueryStr(String group_field, String group, String contributeType, String timeRange,
            String community) {
        String queryStr;
        String queryJson;
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);
        switch (group_field) {
            case "sig":
                queryJson = getSigAggUserQueryStr();
                break;
            case "company":
                queryJson = getCompanyAggUserQueryStr();
                break;
            default:
                return null;
        }
        if (queryJson == null) {
            System.out.println("QueryString is null...");
            return null;
        }

        switch (contributeType.toLowerCase()) {
            case "pr":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, group, "is_pull_state_merged");
                break;
            case "issue":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, group, "is_gitee_issue");
                break;
            case "comment":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, group, "is_gitee_comment");
                break;
            default:
                return null;
        }

        return queryStr;
    }

     public String getAggGroupSigCountQueryStr(String queryJson, String contributeType, String timeRange, String group, String field) {
        String queryStr;    
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);

        switch (contributeType.toLowerCase()) {
            case "pr":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, field, group, "is_pull_state_merged");
                break;
            case "issue":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, field, group, "is_gitee_issue");
                break;
            case "comment":
                queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, field, group, "is_gitee_comment");
                break;
            default:
                return null;
        }
        return queryStr;
    }   

    public String getSigScoreQuery(String queryJson, String timeRange, String sig) {
        if (queryJson == null) {
            System.out.println("QueryStr is null...");
            return null;
        }
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);
        String queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis, sig);
        return queryStr;
    }

    public String getcommonQuery(String queryJson, String timeRange) {
        if (queryJson == null) {
            System.out.println("QueryStr is null...");
            return null;
        }
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);
        String queryStr = String.format(queryJson, lastTimeMillis, currentTimeMillis);
        return queryStr;
    }

    public ArrayList<Object> getAggUserCountQueryParams(String contributeType, String timeRange) {
        long currentTimeMillis = System.currentTimeMillis();
        long lastTimeMillis = getPastTime(timeRange);
        ArrayList<Object> list = new ArrayList<>();
        list.add(contributeType);
        list.add(lastTimeMillis);
        list.add(currentTimeMillis);
        switch (contributeType.toLowerCase()) {
            case "pr":
                list.add("is_pull_state_merged");
                list.add("pull_title");
                list.add("pull_url");
                list.add("pull_id_in_repo");   
                break;
            case "issue":
                list.add("is_gitee_issue");
                list.add("issue_title");
                list.add("issue_url");
                list.add("issue_id_in_repo");
                break;
            case "comment":
                list.add("is_gitee_comment");
                list.add("body");
                list.add("sub_type");
                list.add("id");              
                break;
            default:
                return null;
        }
        return list;
    }

    public String getAggUserListQueryStr(String queryJson, String group, String name) {
        String queryStr;
        if (group == null || name == null) {
            group = "*";
            name = "*";
        }
        switch (group) {
            case "sig":
                queryStr = String.format(queryJson, "sig_names.keyword", name);
                break;
            case "company":
                queryStr = String.format(queryJson, "tag_user_company.keyword", name);
                break;
            case "*":
                queryStr = String.format(queryJson, "user_login.keyword", name);
                break;
            default:
                return null;
        }
        return queryStr;
    }
}


