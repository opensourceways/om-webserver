package com.om.Controller;

import com.om.Result.Result;
import com.om.Result.Success;
import com.om.Service.ContributionDataService;
import com.om.Vo.ContributionVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author xiazhonghai
 * @date 2021/2/1 17:24
 * @description:从es对应index中获取指定的指标数据
 */
@RestController
public class ContributionDataController {
    @Autowired
    ContributionDataService contributionDataService;

    @RequestMapping("/ContributionData")
    public Result getContributionData(@RequestBody ContributionVo co){
        List<Map> allPrIssueComment = contributionDataService.getContributionData(co.getCommunity(),co.getType() , co.getIndividualSearchKey(), co.getOrganizationSearchKey(),
                Integer.parseInt(co.getCurrentPage()), Integer.parseInt(co.getPageSize()), co.getSortKey(), co.getSortValue());
        return new Success().setData(allPrIssueComment).setCode(200).setTotal(allPrIssueComment.size()).setMessage("SUCCESS");

    }
    @RequestMapping("/ContributionDataPie")
    public Map<Object, Object> getDataPie(@RequestBody ContributionVo co){
        List dataPie = contributionDataService.getContributionDataPie(co.getCommunity(), co.getType());
        HashMap<Object, Object> resultmap = new HashMap<>();
        resultmap.put("data",dataPie);
        resultmap.put("code",200);
        resultmap.put("type",co.getType());
        return resultmap;
    }
}
