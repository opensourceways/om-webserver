package com.om.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Service.QueryService;
import com.om.Vo.BlueZoneContributeVo;
import com.om.Vo.BlueZoneUserVo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
    private static Logger logger = LogManager.getLogger(QueryController.class);

    @Autowired
    QueryService queryService;

    @RequestMapping("/contributors")
    public String queryContributors(@RequestParam(value = "community") String community) {
        String contributors = queryService.queryContributors(community);
        return contributors;
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
        String prs = queryService.queryDownload(community, "download");
        return prs;
    }

    @RequestMapping(value="/blueZone/contributes", method=RequestMethod.POST)
    public String queryBlueZoneContributes(@RequestBody BlueZoneContributeVo body) throws InterruptedException, ExecutionException, JsonProcessingException {
        String prs = queryService.queryBlueZoneContributes(body, "contributes");
        return prs;
    }

    @RequestMapping(value="/blueZone/users", method=RequestMethod.POST)
    public String putBlueZoneUser(@RequestBody BlueZoneUserVo userVo) throws InterruptedException, ExecutionException, JsonProcessingException {
        String prs = queryService.putBlueZoneUser(userVo, "users");
        return prs;
    }

    @RequestMapping(value="/starFork", method=RequestMethod.GET)
    public String queryOrgStarAndFork(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException {
        String prs = queryService.queryOrgStarAndFork(community, "starFork");
        return prs;
    }
}

