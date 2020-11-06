package com.om.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Service.QueryService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
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
    public String queryContributors(@RequestParam(value = "community") String community) throws  NoSuchAlgorithmException, KeyManagementException {
            String contributors = queryService.queryContributors(community);
            return contributors;
    }


    @RequestMapping("/sigs")
    public String querySigs(@RequestParam(value = "community") String community) throws NoSuchAlgorithmException, KeyManagementException, InterruptedException, ExecutionException, JsonProcessingException {
        String sigs = queryService.querySigs(community);
        return sigs;
    }

    @RequestMapping("/users")
    public String queryUsers(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        String users = queryService.queryUsers(community);
        return users;
    }

    @RequestMapping("/noticeusers")
    public String queryNoticeusers(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        String noticusers = queryService.queryNoticeusers(community);
        return noticusers;
    }

    @RequestMapping("/modulenums")
    public String queryModulenums(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        String modulenums = queryService.queryModulenums(community);
        return modulenums;

    }
    @RequestMapping("/businessosv")
    public String queryBusinessOsv(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        String modulenums = queryService.queryBusinessOsv(community);
        return modulenums;
    }

    @RequestMapping("/all")
    public String queryAll(@RequestParam(value = "community") String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        String all = queryService.queryAll(community);
        return all;

    }

}

