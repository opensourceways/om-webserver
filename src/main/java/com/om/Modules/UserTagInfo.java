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

package com.om.Modules;

import java.util.Objects;

public class UserTagInfo {
    // giteeId
    private String giteeId;
    // 活跃度
    private double activity;
    //评审意愿
    private double willingness;
    // 在该仓库的PR评论数占比（在该仓库的PR评论数/该仓库所有PR评论）
    private double commentPercentInThisRepo;
    // PR评论总数
    private int commentTotal;
    // 评论过相关PR的相关性
    private double correlation;
    // 繁忙程度
    private int busyness;

    public UserTagInfo() {
    }

    public UserTagInfo(double activity, double willingness, double commentPercentInThisRepo, int commentTotal, double correlation, int busyness) {
        this.activity = activity;
        this.willingness = willingness;
        this.commentPercentInThisRepo = commentPercentInThisRepo;
        this.commentTotal = commentTotal;
        this.correlation = correlation;
        this.busyness = busyness;
    }

    public String getGiteeId() {
        return giteeId;
    }

    public void setGiteeId(String giteeId) {
        this.giteeId = giteeId;
    }

    public double getActivity() {
        return activity;
    }

    public void setActivity(double activity) {
        this.activity = activity;
    }

    public double getWillingness() {
        return willingness;
    }

    public void setWillingness(double willingness) {
        this.willingness = willingness;
    }

    public double getCommentPercentInThisRepo() {
        return commentPercentInThisRepo;
    }

    public void setCommentPercentInThisRepo(double commentPercentInThisRepo) {
        this.commentPercentInThisRepo = commentPercentInThisRepo;
    }

    public int getCommentTotal() {
        return commentTotal;
    }

    public void setCommentTotal(int commentTotal) {
        this.commentTotal = commentTotal;
    }

    public double getCorrelation() {
        return correlation;
    }

    public void setCorrelation(double correlation) {
        this.correlation = correlation;
    }

    public int getBusyness() {
        return busyness;
    }

    public void setBusyness(int busyness) {
        this.busyness = busyness;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserTagInfo that = (UserTagInfo) o;
        return giteeId.equals(that.giteeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(giteeId);
    }
}
