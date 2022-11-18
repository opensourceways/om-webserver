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

package com.om.Modules.yaml;

import java.util.List;

public class GroupYamlInfo {

    public String group;
    public String en_group;
    public List<SigYamlInfo> group_list;

    public String getEngroup() {
        return en_group;
    }

    public void setEngroup(String en_group) {
        this.en_group = en_group;
    }

    public String getgroup() {
        return group;
    }

    public void setgroup(String group) {
        this.group = group;
    }

    public List<SigYamlInfo> getgroup_list() {
        return group_list;
    }

    public void setgroup_list(List<SigYamlInfo> group_list) {
        this.group_list = group_list;
    }
}
