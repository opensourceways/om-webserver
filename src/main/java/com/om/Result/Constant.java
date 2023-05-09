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

package com.om.Result;

/**
 * @author xiazhonghai
 * @date 2021/2/1 18:44
 * @description:常量类
 */
public class Constant {
    public static final String openeuler="openeuler";
    public static final String opengauss="opengauss";
    public static final String openlookeng="openlookeng";
    public static final String mindspore="mindspore";
    public static final String individual="individual";
    public static final String organization="organization";
    public static final String allIssueCveStr="allIssueCveStr";
    public static final String allIssueResult="allIssueResult";
    public static final String PHONEREGEX = "^[a-z0-9]{11}$";
    public static final String EMAILREGEX = "^[A-Za-z0-9-._\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";
    public static final String USERNAMEREGEX = "^[a-zA-Z][0-9a-zA-Z_]{1,18}[0-9a-zA-Z]$";
    public static final String NICKNAMEREGEX = "^[a-zA-Z\\u4e00-\\u9fa5][0-9a-zA-Z_\\u4e00-\\u9fa5]{1,18}[0-9a-zA-Z\\u4e00-\\u9fa5]$";
    public static final String COMPANYNAMEREGEX = "^[0-9a-zA-Z\\u4e00-\\u9fa5][0-9a-zA-Z,\\.&\\(\\)（）\\s\\u4e00-\\u9fa5]{0,98}[0-9a-zA-Z\\.\\u4e00-\\u9fa5]$";

    public static final String FULL_SENSITIVE_REG = "^.*(password|secret|token|code).*$";
    public static final String HALF_SENSITIVE_REG = "^.*(account).*$";
    public static final String PHONE_REPLACE_REG = "(^\\d{3})\\d.*(\\d{4})";
    public static final String EMAIL_REPLACE_REG = "(^\\w)[^@]*(@.*$)";

    public static final String DEFAULT_EXPIRE_SECOND = "60";
    public static final String AUTHING = "authing";
    public static final String ONEID_VERSION_V1 = "openeuler";
    public static final String ONEID_VERSION_V2 = "mindspore";
}

