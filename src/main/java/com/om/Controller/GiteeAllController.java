package com.om.Controller;

import com.om.Result.Result;
import com.om.Service.GiteeAllService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author xiazhonghai
 * @date 2021/2/1 17:24
 * @description:从es对应index中获取指定的指标数据
 */
@RestController
public class GiteeAllController {
    @Autowired
    GiteeAllService giteeAllService;

    @RequestMapping("/IssueData")
    public Result getissuedata(@RequestParam(value = "community") String community,@RequestParam(value = "milestone",required = true) String milestone,
                               @RequestParam(value = "state",defaultValue = "all") String state,@RequestParam(value = "currentPage",defaultValue = "0") String currentPage,
                               @RequestParam(value = "pageSize",defaultValue = "0") String pageSize,@RequestParam(value = "sortKey") String sortKey,@RequestParam(value = "sortValue") String sortValue){
        Result issueData = giteeAllService.getIssueData(community, milestone, state, Integer.parseInt(currentPage), Integer.parseInt(pageSize), sortKey, sortValue);
        return issueData;

    }

}
