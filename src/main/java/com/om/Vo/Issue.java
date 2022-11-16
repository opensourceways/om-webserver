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

/**
 * @author xiazhonghai
 * @date 2021/2/4 15:35
 * @description:
 */
public class Issue {
    String id;
    String title;
    String type;
    String state;
    String description;
    String assigeee;
    String planStartAt;
    String planDeadlineAt;
    String closedAt;
    String mileStone;

    public String getMileStone() {
        return mileStone;
    }

    public void setMileStone(String mileStone) {
        this.mileStone = mileStone;
    }

    public Issue(String id, String title, String type, String state, String description, String assigeee, String planStartAt, String planDeadlineAt, String closedAt, String mileStone) {
        this.id = id;
        this.title = title;
        this.type = type;
        this.state = state;
        this.description = description;
        this.assigeee = assigeee;
        this.planStartAt = planStartAt;
        this.planDeadlineAt = planDeadlineAt;
        this.closedAt = closedAt;
        this.mileStone = mileStone;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }



    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAssigeee() {
        return assigeee;
    }

    public void setAssigeee(String assigeee) {
        this.assigeee = assigeee;
    }

    public String getPlanStartAt() {
        return planStartAt;
    }

    public void setPlanStartAt(String planStartAt) {
        this.planStartAt = planStartAt;
    }

    public String getPlanDeadlineAt() {
        return planDeadlineAt;
    }

    public void setPlanDeadlineAt(String planDeadlineAt) {
        this.planDeadlineAt = planDeadlineAt;
    }

    public String getClosedAt() {
        return closedAt;
    }

    public void setClosedAt(String closedAt) {
        this.closedAt = closedAt;
    }
}
