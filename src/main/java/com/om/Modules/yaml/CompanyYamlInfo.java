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
