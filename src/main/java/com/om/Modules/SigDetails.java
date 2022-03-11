package com.om.Modules;

import java.util.List;

public class SigDetails {
    private String name;
    private String description;
    private List<SigDetailsMaintainer> maintainer;
    private List<String> repositories;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<SigDetailsMaintainer> getMaintainer() {
        return maintainer;
    }

    public void setMaintainer(List<SigDetailsMaintainer> maintainer) {
        this.maintainer = maintainer;
    }

    public List<String> getRepositories() {
        return repositories;
    }

    public void setRepositories(List<String> repositories) {
        this.repositories = repositories;
    }
}

