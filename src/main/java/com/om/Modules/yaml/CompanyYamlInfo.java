package com.om.Modules.yaml;

import java.util.List;

public class CompanyYamlInfo {
    private String company_cn;
    private String company_en;
    private List<String> aliases;

    public String getCompany_cn() {
        return company_cn;
    }

    public void setCompany_cn(String company_cn) {
        this.company_cn = company_cn;
    }

    public String getCompany_en() {
        return company_en;
    }

    public void setCompany_en(String company_en) {
        this.company_en = company_en;
    }

    public List<String> getAliases() {
        return aliases;
    }

    public void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }
}
