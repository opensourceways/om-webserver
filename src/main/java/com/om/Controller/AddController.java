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
    public String addBugQuestionnaire(@RequestParam String community, @RequestBody BugQuestionnaireVo bugQuestionnaireVo) {
        String res = addService.putBugQuestionnaire(community, bugQuestionnaireVo);
        return res;
    }


}
