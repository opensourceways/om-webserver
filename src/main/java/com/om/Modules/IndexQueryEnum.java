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

/**
 * @author zhxia
 * @date 2020/11/5 17:02
 */

    public enum IndexQueryEnum {
    EXTOS("extOs_index", "extOs_queryStr"), BUSINESSOSV("businessOsv_index", "businessOsv_queryStr"), SIGS("sigs_index", "sigs_queryStr"), USERS("users_index", "users_queryStr"),CONTRIUTORS("contributors_index","contributors_queryStr"),NOTICEUSERS("noticeusers_index","noticeusres_queryStr"),COMMUNITYMEMBERS("communitymembers_index","communitymembers_queryStr");
        // 成员变量
        private String index;
        private String queryString;
        // 构造方法
        private IndexQueryEnum(String key, String value) {
            this.index = key;
            this.queryString = value;
        }
        // get set 方法
        public String getIndex() {
            return index;
        }
        public void setIndex(String index) {
            this.index = index;
        }
        public String getQueryString() {
            return queryString;
        }
        public void setQueryString(String value) {
            this.queryString = value;
        }
    }

