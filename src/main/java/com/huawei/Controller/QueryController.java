package com.huawei.Controller;

import com.huawei.Service.QueryService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;


/**
 * @author zhxia
 * @date 2020/10/22 11:40
 */
@Controller
@RequestMapping(value = "/query")
@ResponseBody
public class QueryController {
    private static Logger logger = Logger.getLogger(QueryController.class);

    @Autowired
    QueryService queryService;

    @RequestMapping("/contributors")
    public String queryContributors(@RequestParam(value = "community") String community) {
        try {
            return queryService.queryContributors(community);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return "0";
        }
    }


    @RequestMapping("/sigs")
    public String querySigs(@RequestParam(value = "community") String community) {
        try {
            return queryService.querySigs(community);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return "0";
        }
    }

    @RequestMapping("/users")
    public String queryUsers(@RequestParam(value = "community") String community) {
        try {
            return queryService.queryUsers(community);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return "0";
        }
    }

    @RequestMapping("/noticusers")
    public String queryNoticusers(@RequestParam(value = "community") String community) {
        try {
            return queryService.queryNoticusers(community);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return "0";
        }
    }

    @RequestMapping("/modulenums")
    public String queryModulenums(@RequestParam(value = "community") String community) {
        try {
            return queryService.queryModulenums(community);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return "0";
        }

    }

    @RequestMapping("/all")
    public String queryAll(@RequestParam(value = "community") String community) {
        try {
            return queryService.queryAll(community);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return "0";
        }
    }

}

