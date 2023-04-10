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

package com.om.Service;

import com.om.Dao.AddDao;
import com.om.Modules.meetup.MeetupApplyForm;
import com.om.Modules.meetup.MeetupTranscript;
import com.om.Modules.meetup.MeetupVenueInfo;
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

    public String putBugQuestionnaire(String community, String lang, BugQuestionnaireVo bugQuestionnaireVo) {
        String item = "bugQuestionnaire";
        String res = "";
        lang = lang == null ? "zh" : lang.toLowerCase();
        try {
            res = addDao.putBugQuestionnaire(community, item, lang, bugQuestionnaireVo);
        } catch (Exception e) {
            e.printStackTrace();
        }


        return res;
    }

    public String putMeetupApplyForm(String community, MeetupApplyForm meetupApplyForm, String token) {
        String item = "meetupApplyForm";
        String res = "";
        try {
            res = addDao.putMeetupApplyForm(community, item, meetupApplyForm, token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public String putMeetupVenueInfo(String community, MeetupVenueInfo meetupVenueInfo, String token) {
        String item = "meetupVenueInfo";
        String res = "";
        try {
            res = addDao.putMeetupVenueInfo(community, item, meetupVenueInfo, token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public String putMeetupTranscript(String community, MeetupTranscript meetupTranscript, String token) {
        String item = "meetupTranscript";
        String res = "";
        try {
            res = addDao.putMeetupTranscript(community, item, meetupTranscript, token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

}
