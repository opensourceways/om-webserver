/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.om.Result.Result;
import com.om.Result.Success;
import com.om.Service.GiteeIssueService;
import com.om.Vo.MilestoneForIssueVo;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



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
        Map issueData =giteeAllService.getIssueData(vo.getCommunity(), vo.getMilestone(), vo.getState(), Integer.parseInt(vo.getCurrentPage()),
                Integer.parseInt(vo.getPageSize()), vo.getSortKey(), vo.getSortValue());

        return new Success().setData((List) issueData.get("data")).setCode(200).setTotal((int)issueData.get("total")).setMessage("SUCCESS");
    }
    @RequestMapping("/CVEData")
    public Result getCveData(@RequestBody MilestoneForIssueVo vo) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
            Map cveData = giteeAllService.getCveData(vo);
            return new Success().setData((List) cveData.get("data")).setCode(200).setTotal((int)cveData.get("total")).setMessage("SUCCESS");
    }
}