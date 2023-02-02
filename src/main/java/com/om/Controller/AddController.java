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


import com.om.Service.AddService;
import com.om.Vo.BugQuestionnaireVo;
import com.om.token.UserLoginToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * @author caimingdeng
 * @date 2022/10/11 11:40
 */
@RequestMapping(value = "/add")
@RestController
public class AddController {

    @Autowired
    AddService addService;

    @UserLoginToken
    @RequestMapping(value = "/bugquestionnaire", method = RequestMethod.POST)
    public String addBugQuestionnaire(@RequestParam String community, @RequestParam(value = "lang", required = false) String lang, @RequestBody BugQuestionnaireVo bugQuestionnaireVo) {
        String res = addService.putBugQuestionnaire(community, lang, bugQuestionnaireVo);
        return res;
    }


}
