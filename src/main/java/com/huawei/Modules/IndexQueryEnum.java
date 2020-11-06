package com.huawei.Modules;

/**
 * @author zhxia
 * @date 2020/11/5 17:02
 */

    public enum IndexQueryEnum {
    EXTOS("extOs_index", "extOs_queryStr"), BUSINESSOSV("businessOsv_index", "businessOsv_queryStr"), SIGS("sigs_index", "sigs_queryStr"), USERS("users_index", "users_queryStr"),CONTRIUTORS("contributors_index","contributors_queryStr"),NOTICEUSERS("noticeusers_index","noticeusres_queryStr");
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

