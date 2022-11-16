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

package com.om.Vo;

import java.util.List;

public class BlueZoneContributeVo {
    private String token;
    private String startTime;
    private String endTime;
    private List<String> gitee_id;
    private List<String> github_id;

    public List<String> getGitee_id() {
        return gitee_id;
    }

    public void setGitee_id(List<String> gitee_id) {
        this.gitee_id = gitee_id;
    }

    public List<String> getGithub_id() {
        return github_id;
    }

    public void setGithub_id(List<String> github_id) {
        this.github_id = github_id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getStartTime() {
        return startTime;
    }

    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }

    public String getEndTime() {
        return endTime;
    }

    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }
}
