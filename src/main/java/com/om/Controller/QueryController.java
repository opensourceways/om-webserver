package com.om.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.om.Service.QueryService;
import com.om.Vo.*;
import com.om.authing.AuthingToken;
import com.om.token.UserLoginToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.ExecutionException;


/**
 * @author zhxia
 * @date 2020/10/22 11:40
 */
@RequestMapping(value = "/query")
@RestController
public class QueryController {

    @Autowired
    QueryService queryService;

    @RequestMapping("/contributors")
    public String queryContributors(@RequestParam(value = "community") String community) {
        String contributors = queryService.queryContributors(community);
        return contributors;
    }

    @RequestMapping("/avgduration")
    public String queryDurationAggFromProjectHostarchPackage(@RequestParam(value = "community") String community) {
        String avgDuration = queryService.queryDurationAggFromProjectHostarchPackage(community);
        return avgDuration;
    }

    @RequestMapping("/sigs")
    public String querySigs(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String sigs = queryService.querySigs(community);
        return sigs;
    }

    @RequestMapping("/users")
    public String queryUsers(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String users = queryService.queryUsers(community);
        return users;
    }

    @RequestMapping("/noticeusers")
    public String queryNoticeusers(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String noticusers = queryService.queryNoticeusers(community);
        return noticusers;
    }

    @RequestMapping("/modulenums")
    public String queryModulenums(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String modulenums = queryService.queryModulenums(community);
        return modulenums;
    }

    @RequestMapping("/businessosv")
    public String queryBusinessOsv(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String modulenums = queryService.queryBusinessOsv(community);
        return modulenums;
    }

    @RequestMapping("/communitymembers")
    public String querycommunitymembers(@RequestParam(value = "community") String community) {
        String modulenums = queryService.querycommunitymembers(community);
        return modulenums;
    }

    @RequestMapping("/all")
    public String queryAll(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String all = queryService.queryAll(community);
        return all;
    }

    //TODO 以下四个接口，仅测试过MindSpore
    @RequestMapping("/stars")
    public String queryStars(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String starts = queryService.queryCount(community, "stars");
        return starts;
    }

    @RequestMapping("/issues")
    public String queryIssues(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String issues = queryService.queryCount(community, "issues");
        return issues;
    }

    @RequestMapping("/prs")
    public String queryPrs(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String prs = queryService.queryCount(community, "prs");
        return prs;
    }

    @RequestMapping("/downloads")
    public String queryDownloads(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.queryDownload(community, "download");
        return res;
    }

    @RequestMapping(value = "/blueZone/contributes", method = RequestMethod.POST)
    public String queryBlueZoneContributes(@RequestBody BlueZoneContributeVo body) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.queryBlueZoneContributes(body, "contributes");
        return res;
    }

    @RequestMapping(value = "/blueZone/users", method = RequestMethod.POST)
    public String putBlueZoneUser(@RequestBody BlueZoneUserVo userVo) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.putBlueZoneUser(userVo, "users");
        return res;
    }

    @RequestMapping(value = "/starFork", method = RequestMethod.GET)
    public String queryOrgStarAndFork(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.queryOrgStarAndFork(community, "starFork");
        return res;
    }

    @UserLoginToken
    @RequestMapping(value = "/cveDetails", method = RequestMethod.GET)
    public String queryOrgStarAndFork(@RequestParam(value = "community") String community,
                                      @RequestParam(value = "lastCursor", required = false) String lastCursor,
                                      @RequestParam(value = "pageSize", required = false) String pageSize) {

        String res = queryService.queryCveDetails(community, "cveDetails", lastCursor, pageSize);
        return res;
    }

//    @RequestMapping("/newYear/2022")
    @RequestMapping("/lts/2203")
    public String queryNewYear(@RequestParam(value = "community") String community, @RequestParam(value = "user") String user) {
//        String res = queryService.queryNewYear(community, user, "2022");
        String res = queryService.queryNewYear(community, user, "2203lts");
        return res;
    }

    @UserLoginToken
    @RequestMapping("/bugQuestionnaires")
    public String queryBugQuestionnaires(@RequestParam(value = "community") String community,
                                         @RequestParam(value = "lastCursor", required = false) String lastCursor,
                                         @RequestParam(value = "pageSize", required = false) String pageSize) {
        String res = queryService.queryBugQuestionnaire(community, "bugQuestionnaire", lastCursor, pageSize);
        return res;
    }

    @RequestMapping("/obsDetails")
    public String queryObsDetails(@RequestParam(value = "community") String community,
                                  @RequestParam(value = "branch") String branch,
                                  @RequestParam(value = "limit", required = false) String limit) {
        String res = queryService.queryObsDetails(community, "obsDetails", branch, limit);
        return res;
    }

    @RequestMapping(value = "/isoBuildTimes", method = RequestMethod.POST)
    public String queryIsoBuildTimes(@RequestBody IsoBuildTimesVo body) {
        String res = queryService.queryIsoBuildTimes(body, "isoBuildTimes");
        return res;
    }

    @RequestMapping(value = "/sigDetails", method = RequestMethod.POST)
    public String querySigDetails(@RequestBody SigDetailsVo body) {
        String res = queryService.querySigDetails(body, "sigDetails");
        return res;
    }

    @RequestMapping("/company/contribute")
    public String queryCompanyContributors(@RequestParam(value = "community") String community,
                                           @RequestParam(value = "contributeType") String contributeType,
                                           @RequestParam(value = "timeRange") String timeRange,
                                           @RequestParam(value = "repo", required = false) String repo) {
        String res = queryService.queryCompanyContributors(community, "companyContribute", contributeType, timeRange, repo);
        return res;
    }

    @RequestMapping("/user/contribute")
    public String queryUserContributors(@RequestParam(value = "community") String community,
                                        @RequestParam(value = "contributeType") String contributeType,
                                        @RequestParam(value = "timeRange") String timeRange,
                                        @RequestParam(value = "repo", required = false) String repo) {
        String res = queryService.queryUserContributors(community, "userContribute", contributeType, timeRange, repo);
        return res;
    }

    @RequestMapping(value = "/issueScore", method = RequestMethod.GET)
    public String queryIssueScore(@RequestParam(value = "community") String community,
                                  @RequestParam(value = "start_date", required = false) String start_date,
                                  @RequestParam(value = "end_date", required = false) String end_date) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.queryIssueScore(community, start_date, end_date, "issueScore");
        return res;
    }


    @RequestMapping(value = "/buildCheckInfo", method = RequestMethod.POST)
    public String queryBuildCheckInfo(@RequestBody BuildCheckInfoQueryVo queryBody) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.queryBuildCheckInfo(queryBody,"buildCheckInfo");
        return res;
    }

    @RequestMapping(value = "/track", method = RequestMethod.GET)
    public String putUserActionsinfo(@RequestParam(value = "community") String community, 
                                     @RequestParam(value = "data") String data, 
                                     @RequestParam(value = "ext") String ext) throws InterruptedException, ExecutionException, JsonProcessingException {
        String res = queryService.putUserActionsinfo(community, data);
        return res;
    }

    @RequestMapping("/sig/name")
    public String querySigName(@RequestParam(value = "community") String community) throws JsonProcessingException, InterruptedException, ExecutionException {
        String res = queryService.querySigName(community);
        return res;
    }

    @RequestMapping("/sig/info")
    public String querySigInfo(@RequestParam(value = "community") String community,
            @RequestParam(value = "sig", required = false) String sig,
            @RequestParam(value = "repo", required = false) String repo,
            @RequestParam(value = "user", required = false) String user,
            @RequestParam(value = "search", required = false) String search,
            @RequestParam(value = "page", required = false) String page,
            @RequestParam(value = "pageSize", required = false) String pageSize) throws JsonMappingException, JsonProcessingException {
        String res = queryService.querySigInfo(community, sig, repo, user, search, page, pageSize);
        return res;
    }

    @RequestMapping("/sig/repo")
    public String querySigRepo(@RequestParam(value = "community") String community,
            @RequestParam(value = "sig", required = false) String sig,
            @RequestParam(value = "page", required = false) String page,
            @RequestParam(value = "pageSize", required = false) String pageSize) throws JsonMappingException, JsonProcessingException {
        String res = queryService.querySigRepo(community, sig, page, pageSize);
        return res;
    }

    // @AuthingToken
    @RequestMapping("sig/company/contribute")
    public String querySigCompanyContributors(@RequestParam(value = "community") String community,
                                           @RequestParam(value = "contributeType") String contributeType,
                                           @RequestParam(value = "timeRange") String timeRange,
                                           @RequestParam(value = "sig", required = false) String sig) {
        String res = queryService.querySigCompanyContributors(community, "companyContribute", contributeType, timeRange, sig);
        return res;
    }

    @RequestMapping("/company/name")
    public String queryCompanyName(@RequestParam(value = "community") String community) throws JsonProcessingException, InterruptedException, ExecutionException {
        String res = queryService.queryCompanyName(community);
        return res;
    }

    @AuthingToken
    @RequestMapping("/company/usercontribute")
    public String queryCompanyUsercontribute(@RequestParam(value = "community") String community, 
                                             @RequestParam(value = "company") String company, 
                                             @RequestParam(value = "contributeType") String contributeType, 
                                             @RequestParam(value = "timeRange") String timeRange,
                                             @CookieValue("_Y_G_") String token) {
        String res = queryService.queryCompanyUsercontribute(community, company, contributeType, timeRange, token);
        return res;
    }

    @AuthingToken
    @RequestMapping("/company/sigcontribute")
    public String queryCompanySigcontribute(@RequestParam(value = "community") String community, 
                                            @RequestParam(value = "company") String company, 
                                            @RequestParam(value = "contributeType") String contributeType, 
                                            @RequestParam(value = "timeRange") String timeRange,
                                            @CookieValue("_Y_G_") String token) {
        String res = queryService.queryCompanySigcontribute(community, company, contributeType, timeRange, token);
        return res;
    }

    @AuthingToken
    @RequestMapping("/company/sigdetails")
    public String queryCompanySigDetails(@RequestParam(value = "community") String community, 
                                         @RequestParam(value = "company") String company, 
                                         @RequestParam(value = "timeRange") String timeRange,
                                         @CookieValue("_Y_G_") String token) {
        String res = queryService.queryCompanySigDetails(community, company, timeRange, token);
        return res;
    }

    //@AuthingToken
    @RequestMapping("/sig/usercontribute")
    public String querySigUserTypeCount(@RequestParam(value = "community") String community, @RequestParam(value = "sig") String sig, 
                                        @RequestParam(value = "contributeType") String contributeType, @RequestParam(value = "timeRange") String timeRange) {
        String res = queryService.querySigUserTypeCount(community, sig, contributeType, timeRange);
        return res;
    }

    @AuthingToken
    @RequestMapping("/company/users")
    public String queryCompanyUsers(@RequestParam(value = "community") String community, 
                                    @RequestParam(value = "company") String company, 
                                    @RequestParam(value = "timeRange") String timeRange,
                                    @CookieValue("_Y_G_") String token) {
        String res = queryService.queryCompanyUsers(community, company, timeRange, token);
        return res;
    }

    @RequestMapping("/community/repos")
    public String queryRepos(@RequestParam(value = "community") String community) {
        String repos = queryService.queryCommunityRepos(community);
        return repos;
    }
    
    @AuthingToken
    @RequestMapping("/sig/score")
    public String querySigScore(@RequestParam(value = "community") String community, 
                                @RequestParam(value = "sig") String sig, 
                                @RequestParam(value = "timeRange") String timeRange) {
        String res = queryService.querySigScore(community, sig, timeRange);
        return res;
    }

    //@AuthingToken
    @RequestMapping("/sig/scoreAll")
    public String querySigScoreAll(@RequestParam(value = "community") String community) {
        String res = queryService.querySigScoreAll(community);
        return res;
    }

    @AuthingToken
    @RequestMapping("/sig/radarscore")
    public String querySigRadarScore(@RequestParam(value = "community") String community, @RequestParam(value = "sig") String sig, 
                               @RequestParam(value = "timeRange") String timeRange) {
        String res = queryService.querySigRadarScore(community, sig, timeRange);
        return res;
    }

    //@AuthingToken
    @RequestMapping("/company/sigs")
    public String queryCompanySigs(@RequestParam(value = "community") String community, @RequestParam(value = "timeRange") String timeRange) {
        String res = queryService.queryCompanySigs(community, timeRange);
        return res;
    }

    @RequestMapping("/TC/sigs")
    public String querySigsOfTCOwners(@RequestParam(value = "community") String community) {
        String res = queryService.querySigsOfTCOwners(community);
        return res;
    }

    //@AuthingToken
    @RequestMapping("/user/sigcontribute")
    public String queryUserSigcontribute(@RequestParam(value = "community") String community, @RequestParam(value = "user") String user, 
                                        @RequestParam(value = "contributeType") String contributeType, @RequestParam(value = "timeRange") String timeRange) {
        String res = queryService.queryUserSigcontribute(community, user, contributeType, timeRange);
        return res;
    }

    @RequestMapping("/user/ownertype")
    public String queryUserOwnertype(@RequestParam(value = "community") String community, @RequestParam(value = "user") String user) throws JsonMappingException, JsonProcessingException {
        String res = queryService.queryUserOwnertype(community, user);
        return res;
    }

    //@AuthingToken
    @RequestMapping("/user/contribute/details")
    public String queryUserContributeDetails(@RequestParam(value = "community") String community, @RequestParam(value = "user") String user,
                                      @RequestParam(value = "sig", required = false) String sig,
                                      @RequestParam(value = "comment_type", required = false) String comment_type,
                                      @RequestParam(value = "filter", required = false) String filter,
                                      @RequestParam(value = "contributeType") String contributeType, @RequestParam(value = "timeRange") String timeRange,
                                      @RequestParam(value = "page", required = false) String page,
                                      @RequestParam(value = "pageSize", required = false) String pageSize) throws JsonMappingException, JsonProcessingException {
        String res = queryService.queryUserContributeDetails(community, user, sig, contributeType, timeRange, page, pageSize, comment_type, filter);
        return res;
    }

    @RequestMapping("/userlist")
    public String queryUserLists(@RequestParam(value = "community") String community,
            @RequestParam(value = "group", required = false) String group,
            @RequestParam(value = "name", required = false) String name) {
        String res = queryService.queryUserLists(community, group, name);
        return res;
    }

    @RequestMapping("/sig/repo/committers")
    public String querySigRepoCommitters(@RequestParam(value = "community") String community, @RequestParam(value = "sig") String sig) {
        String res = queryService.querySigRepoCommitters(community, sig);
        return res;
    }

    @RequestMapping(value = "/ip/location")
    public String getIPLocation(@RequestParam(value = "ip") String ip) {
        return queryService.getIPLocation(ip);
    }

    @RequestMapping(value = "ecosystem/repo/info")
    public String getEcosystemRepoInfo(@RequestParam(value = "community") String community,
            @RequestParam(value = "ecosystem_type") String ecosystem_type,
            @RequestParam(value = "sort_type", required = false) String sort_type,
            @RequestParam(value = "sort_order", required = false) String sort_order,
            @RequestParam(value = "page", required = false) String page,
            @RequestParam(value = "pageSize", required = false) String pageSize) throws JsonMappingException, JsonProcessingException {
        return queryService.getEcosystemRepoInfo(community, ecosystem_type, sort_type, sort_order, page, pageSize);
    }
}
