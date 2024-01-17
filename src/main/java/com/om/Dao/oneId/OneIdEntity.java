package com.om.Dao.oneId;

import lombok.Getter;
import lombok.Setter;

import java.sql.Date;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

public class OneIdEntity {

    @Getter
    @Setter
    public static class App {

        private String id;

        private String appId;

        private String appSecret;

        private String userPoolId;

        private String appName;

        private Timestamp createAt;

        private Timestamp updateAt;

        private String redirectUrls;

    }

    @Getter
    @Setter
    public static class GetManagementToken {

        private String accessKeyId;

        private String accessKeySecret;
    }

    @Getter
    @Setter
    public static class User {
        private String id;

        private String userPoolId;

        private String address;

        private Date birthdate;

        private String city;

        private String company;

        private String country;

        private String email;

        private boolean emailVerified;

        private String familyName;

        private String formatted;

        private String gender;

        private String givenName;

        private String locale;

        private String middleName;

        private String name;

        private String nickname;

        private String password;

        private String salt;

        private String phone;

        private String phoneCountryCode;

        private boolean phoneVerified;

        private String photo;

        private String postalCode;

        private String province;

        private String region;

        private String streetAddress;

        private String username;

        private String zoneinfo;

        private Timestamp createAt;

        private Timestamp updateAt;

        private List<ThirdPartyUser> identities = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class ThirdPartyClient {
        
        private String id;

        private String name;

        private String description;

        private String icon;

        private String authorizeUrl;

        private String tokenUrl;

        private String userUrl;

        private String clientId;

        private String clientSecret;

        private String scopes;
    }

    @Getter
    @Setter
    public static class ThirdPartyUser {

        private String id;
    
        private String provider;
    
        private String username;
    
        private String nickname;
    
        private String familyName;
    
        private String middleName;
    
        private String name;
    
        private String gender;
    
        private String profile;
    
        private String photo;
    
        private String city;
    
        private String company;
    
        private String email;
    
        private boolean emailVerified;
    
        private String phone;
    
        private boolean phoneVerified;
    
        private boolean isSocial;
    
        private String userPoolId;
    
        private String extIdpId;
    
        private String userId;
    
        private String userIdInIdp;
    
        private String openid;
    
        private String syncIdentityProviderId;
    
        private String type;
    
        private String blog;
    
        private String weibo;
    
        private String wechat;
    
        private String qq;
    
        private String accessToken;
    
        private String refreshToken;
    
        private Timestamp createdAt;
    
        private Timestamp updatedAt;
    }
}
