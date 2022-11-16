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

import java.util.Map;

public class BuildCheckInfoQueryVo {
    private String community_name;
    private String pr_url;
    private String pr_title;
    private String pr_committer;
    private String pr_branch;
    private String build_no;
    private String check_total;
    private Map<String, String> build_duration;
    private Map<String, String> pr_create_time;
    private Map<String, String> result_update_time;
    private Map<String, String> result_build_time;
    private Map<String, String> mistake_update_time;

    public String getCommunity_name() {
        return community_name;
    }

    public void setCommunity_name(String community_name) {
        this.community_name = community_name;
    }

    public String getPr_url() {
        return pr_url;
    }

    public void setPr_url(String pr_url) {
        this.pr_url = pr_url;
    }

    public String getPr_title() {
        return pr_title;
    }

    public void setPr_title(String pr_title) {
        this.pr_title = pr_title;
    }

    public String getPr_committer() {
        return pr_committer;
    }

    public void setPr_committer(String pr_committer) {
        this.pr_committer = pr_committer;
    }

    public String getPr_branch() {
        return pr_branch;
    }

    public void setPr_branch(String pr_branch) {
        this.pr_branch = pr_branch;
    }

    public String getBuild_no() {
        return build_no;
    }

    public void setBuild_no(String build_no) {
        this.build_no = build_no;
    }

    public String getCheck_total() {
        return check_total;
    }

    public void setCheck_total(String check_total) {
        this.check_total = check_total;
    }

    public Map<String, String> getBuild_duration() {
        return build_duration;
    }

    public void setBuild_duration(Map<String, String> build_duration) {
        this.build_duration = build_duration;
    }

    public Map<String, String> getPr_create_time() {
        return pr_create_time;
    }

    public void setPr_create_time(Map<String, String> pr_create_time) {
        this.pr_create_time = pr_create_time;
    }

    public Map<String, String> getResult_update_time() {
        return result_update_time;
    }

    public void setResult_update_time(Map<String, String> result_update_time) {
        this.result_update_time = result_update_time;
    }

    public Map<String, String> getResult_build_time() {
        return result_build_time;
    }

    public void setResult_build_time(Map<String, String> result_build_time) {
        this.result_build_time = result_build_time;
    }

    public Map<String, String> getMistake_update_time() {
        return mistake_update_time;
    }

    public void setMistake_update_time(Map<String, String> mistake_update_time) {
        this.mistake_update_time = mistake_update_time;
    }
}
