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

import java.util.ArrayList;

public class BugQuestionnaireVo {

    private String bugDocFragment;
    private ArrayList<String> existProblem = new ArrayList<>();
    private String problemDetail;
    private Integer comprehensiveSatisfication;
    private String participateReason;
    private String email;
    private String created_at;

    public String getBugDocFragment() {
        return bugDocFragment;
    }

    public void setBugDocFragment(String bugDocFragment) {
        this.bugDocFragment = bugDocFragment;
    }

    public ArrayList<String> getExistProblem() {
        return existProblem;
    }

    public void setExistProblem(ArrayList<String> existProblem) {
        this.existProblem = existProblem;
    }

    public String getProblemDetail() {
        return problemDetail;
    }

    public void setProblemDetail(String problemDetail) {
        this.problemDetail = problemDetail;
    }

    public Integer getComprehensiveSatisfication() {
        return comprehensiveSatisfication;
    }

    public void setComprehensiveSatisfication(Integer comprehensiveSatisfication) {
        this.comprehensiveSatisfication = comprehensiveSatisfication;
    }

    public String getParticipateReason() {
        return participateReason;
    }

    public void setParticipateReason(String participateReason) {
        this.participateReason = participateReason;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getCreated_at() {
        return created_at;
    }

    public void setCreated_at(String created_at) {
        this.created_at = created_at;
    }
}
