package com.om.Service;

import com.om.Dao.AddDao;
import com.om.Vo.BugQuestionnaireVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author caimingdeng
 * @date 2022/02/11 11:40
 */

@Service
public class AddService {

    @Autowired
    AddDao addDao;

    public String putBugQuestionnaire(String community, BugQuestionnaireVo bugQuestionnaireVo) {
        String item = "bugQuestionnaire";
        String res = "";
        try {
            res = addDao.putBugQuestionnaire(community, item, bugQuestionnaireVo);
        } catch (Exception e) {
            e.printStackTrace();
        }


        return res;
    }


}
