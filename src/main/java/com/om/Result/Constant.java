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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
    public static final String PHONEREGEX = "^1[0-9]{10}$";
    public static final String EMAILREGEX = "^[A-Za-z0-9-._\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";
    public static final String USERNAMEREGEX = "^[a-zA-Z][0-9a-zA-Z_]{1,18}[0-9a-zA-Z]$";
    public static final String THIRDUSERNAMEREGEX = "^[a-z][a-zA-Z0-9_.-]{0,18}[a-z0-9]$";
    public static final String NICKNAMEREGEX = "^[a-zA-Z\\u4e00-\\u9fa5][0-9a-zA-Z_\\u4e00-\\u9fa5]{1,18}[0-9a-zA-Z\\u4e00-\\u9fa5]$";
    public static final String COMPANYNAMEREGEX = "^[0-9a-zA-Z\\u4e00-\\u9fa5][0-9a-zA-Z,\\.&\\(\\)（）\\s\\u4e00-\\u9fa5]{0,98}[0-9a-zA-Z\\.\\u4e00-\\u9fa5]$";

    public static final String FULL_SENSITIVE_REG = "^.*(password|secret|token|code).*$";
    public static final String HALF_SENSITIVE_REG = "^.*(account).*$";
    public static final String PHONE_REPLACE_REG = "(^\\d{3})\\d.*(\\d{4})";
    public static final String EMAIL_REPLACE_REG = "(^\\w)[^@]*(@.*$)";

    public static final String DEFAULT_EXPIRE_SECOND = "60";
    public static final String ONEID_EXPIRE_SECOND = "3000";
    public static final String AUTHING = "authing";
    public static final String ONEID_VERSION_V1 = "openeuler";
    public static final String ONEID_VERSION_V2 = "mindspore";

    public static final String SUCCESS = "success";
    public static final String EMAIL_TYPE = "email";
    public static final String PHONE_TYPE = "phone";
    public static final String USERNAME_TYPE = "username";
    public static final String DEFAULT_EXPIRE_MINUTE = "1";
    public static final String DEFAULT_CODE_LENGTH = "6";

    public static final String CHANNEL_REGISTER = "channel_register";
    public static final String CHANNEL_REGISTER_BY_PASSWORD = "channel_register_by_password";
    public static final String CHANNEL_LOGIN = "channel_login";
    public static final String CHANNEL_RESET_PASSWORD = "channel_reset_password";

    public static final int RANDOM_DEFAULT_LENGTH = 32;
    public static final String NEED_CAPTCHA_VERIFICATION = "need_captcha_verification";
    public static final String NEED_CAPTCHA_VERIFICATION_LIMIT = "3";
    public static final String LOGIN_ERROR_LIMIT = "6";
    public static final String LOGIN_COUNT = "loginCount";
    public static final String SEND_CODE = "_sendCode_";
    public static final String REGISTER_SUFFIX = "_register";
    public static final String RESET_PASSWORD_SUFFIX = "_reset_password";
    public static final String ONEID_TOKEN_KEY = "Oneid-Token";
    public static final String ID_TOKEN_PREFIX = "idToken_";
    public static final String TOKEN_EXPIRES = "token expires";
    public static final String PRIVACY_VERSION_RECORD_TIME = "time";
    public static final String PRIVACY_VERSION_RECORD_OPERATE = "opt";
    public static final String PRIVACY_VERSION_RECORD_ACCEPT = "accept";
    public static final String PRIVACY_VERSION_RECORD_REVOKE = "revoke";
    public static final String PRIVACY_VERSION_RECORD_VERSION = "privacyAccepted";
    public static final String PRIVACY_VERSION_RECORD_HISTORY = "privacyHistory";

    public static final String TOKEN_Y_G_ = "_Y_G_";
    public static final String TOKEN_U_T_ = "_U_T_";
 
    public static final String ONEID_USER_C_PATH = "/composite-user";
    public static final String ONEID_USER_URD_PATH = "/composite-user/{account}";
    public static final String ONEID_CHECK_PASSWORD_PATH = "/auth/check-password/{account}";
    public static final String ONEID_TOKEN_PATH = "/auth/get-management-token";

    public static final String ONEID_APP_PATH = "/app";
    public static final String ONEID_APP_ID_PATH = "/app/{appId}";
    public static final String ONEID_APP_VERIFY_PATH = "/app/verify";

    public static final String ONEID_THIRD_PARTY_ASSOCIATION_PATH = "/third-party-association";
    public static final String ONEID_THIRD_PARTY_CLIENT_GET_PATH = "/third-party-client/%s";
    public static final String ONEID_THIRD_PARTY_USER_GET_PATH = "/composite-user/external/%s";
    public static final String ONEID_THIRD_PARTY_USER_GET_PROVIDER_PATH = "/external-user/get";
    public static final String ONEID_THIRD_PARTY_USER_CREATE_PATH = "/external-user/%s";
    public static final String ONEID_THIRD_PARTY_USER_DELETE_PATH = "/external-user/%s";

    public static final String PHOTO_NOT_ALLOWED_CHARS = "\\,/,:,*,?,\",<,>,|";
    public static final String CONSENT_ACCEPT_TERM = "0";

    public static final String OIDCISSUER = "ONEID";

    /**
     * gitcode.
     */
    public static final String GITCODE = "gitcode";
}

