package com.om.Dao.oneId;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

public class OneIdEntity {

    @Getter
    @Setter
    public static class App {

        private String id;

        private String appId;

        private String appSecret;

        private String userPoolId;

        private String appName;

        private LocalDateTime createAt;

        private LocalDateTime updateAt;

        private String redirectUrls;

    }

    @Getter
    @Setter
    public static class GetManagementToken {

        private String accessKeyId;

        private String accessKeySecret;
    }

}
