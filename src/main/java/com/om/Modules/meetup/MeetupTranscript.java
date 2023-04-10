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
public class MeetupTranscript {
    private int meetupNum;
    private int signUpNum;
    private int attendNum;
    private ArrayList<String> photos;
    private String satisfaction;
    private String hasNewUser;
    private String hasUserCase;
    private String significance;
    private String summary;
}
