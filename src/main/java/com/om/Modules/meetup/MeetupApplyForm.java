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

package com.om.Modules.meetup;

import java.util.ArrayList;

import lombok.Data;

@Data
public class MeetupApplyForm {
    private String company;
    private String topic;
    private String date;
    private SurveyAnswer duration;
    private String city;
    private String meetupSize;
    private String principalUser;
    private String principalCompany;
    private String principalPhone;
    private String principalEmail;
    private SurveyAnswer meetupFormat;
    private ArrayList<SurveyAnswer> supports;
    private String details;
}
