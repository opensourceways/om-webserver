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


import com.om.Modules.meetup.MeetupApplyForm;
import com.om.Modules.meetup.MeetupTranscript;
import com.om.Modules.meetup.MeetupVenueInfo;
import com.om.Service.AddService;
import com.om.Vo.BugQuestionnaireVo;
import com.om.authing.AuthingToken;
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

    @AuthingToken
    @RequestMapping(value = "/meetupApplyForm", method = RequestMethod.POST)
    public String addMeetupApplyForm(@RequestParam String community, @RequestBody MeetupApplyForm meetupApplyForm,
            @CookieValue(value = "_Y_G_", required = false) String token) {
        String res = addService.putMeetupApplyForm(community, meetupApplyForm, token);
        return res;
    }

    @AuthingToken
    @RequestMapping(value = "/meetupVenueInfo", method = RequestMethod.POST)
    public String addMeetupVenueInfo(@RequestParam String community, @RequestBody MeetupVenueInfo meetupVenueInfo,
            @CookieValue(value = "_Y_G_", required = false) String token) {
        String res = addService.putMeetupVenueInfo(community, meetupVenueInfo, token);
        return res;
    }

    @AuthingToken
    @RequestMapping(value = "/meetupTranscript", method = RequestMethod.POST)
    public String addMeetupTranscript(@RequestParam String community, @RequestBody MeetupTranscript meetupTranscript,
            @CookieValue(value = "_Y_G_", required = false) String token) {
        String res = addService.putMeetupTranscript(community, meetupTranscript, token);
        return res;
    }
}
