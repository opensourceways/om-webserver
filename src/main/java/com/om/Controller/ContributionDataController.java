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

import com.om.Result.Result;
import com.om.Result.Success;
import com.om.Service.ContributionDataService;
import com.om.Vo.ContributionResultVoPie;
import com.om.Vo.ContributionVo;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


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
        Map<String,Object> allPrIssueComment = contributionDataService.getContributionData(co.getCommunity(),co.getType() , co.getIndividualSearchKey(), co.getOrganizationSearchKey(),
                Integer.parseInt(co.getCurrentPage()), Integer.parseInt(co.getPageSize()), co.getSortKey(), co.getSortValue());
        return new Success().setData((List) allPrIssueComment.get("data")).setCode(200).setTotal((Integer)allPrIssueComment.get("total")).setMessage("SUCCESS");

    }
    @RequestMapping("/ContributionDataPie")
    public Map<Object, Object> getDataPie(@RequestBody ContributionVo co){
        List<ContributionResultVoPie> dataPie = contributionDataService.getContributionDataPie(co.getCommunity(), co.getType());
        HashMap<Object, Object> resultmap = new HashMap<>();
        resultmap.put("data",dataPie);
        int total=0;
        for (ContributionResultVoPie contributionResultVoPie : dataPie) {
            total+=contributionResultVoPie.getNumber();
        }
        resultmap.put("code",200);
        resultmap.put("total",total);
        resultmap.put("type",co.getType());
        return resultmap;
    }
}
