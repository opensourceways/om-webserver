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
