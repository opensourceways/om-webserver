package com.om.Controller;

import com.om.Result.Result;
import com.om.Result.Success;
import com.om.Service.GiteeIssueService;
import com.om.Vo.MilestoneForIssueVo;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;


/**
 * @author xiazhonghai
 * @date 2021/2/1 17:24
 * @description:020210201wangyiru需求根据里程碑信息，获取里程碑中所有issue
 */
@RestController
public class GiteeIssueController {
    @Autowired
    GiteeIssueService giteeAllService;

    @RequestMapping("/IssueData")
    public Result getissuedata(@RequestBody MilestoneForIssueVo vo){
        String currentPage = vo.getCurrentPage();
        String pageSize = vo.getPageSize();
        int page=0;
        int size=0;
        if(StringUtils.isBlank(currentPage)){
            vo.setCurrentPage("0");
            vo.setPageSize("0");
        }
        ArrayList issueData = (ArrayList) giteeAllService.getIssueData(vo.getCommunity(), vo.getMilestone(), vo.getState(), Integer.parseInt(vo.getCurrentPage()),
                Integer.parseInt(vo.getPageSize()), vo.getSortKey(), vo.getSortValue());
        return new Success().setData(issueData).setCode(200).setTotal(issueData.size()).setMessage("SUCCESS");

    }

}
