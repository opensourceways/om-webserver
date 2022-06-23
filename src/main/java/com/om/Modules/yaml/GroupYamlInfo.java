package com.om.Modules.yaml;

import java.util.List;

public class GroupYamlInfo {

    public String group;
    public List<SigYamlInfo> group_list;

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
