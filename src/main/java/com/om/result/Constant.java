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

package com.om.result;

/**
 * 常量类.
 */
public final class Constant {
    private Constant() {
        throw new AssertionError("Utility class. Not intended for instantiation.");
    }
    /**
     * 外部请求socket超时时间30s.
     */
    public static final Integer SOCKET_TIMEOUT = 30000;

    /**
     * 外部请求connect超时时间10s.
     */
    public static final Integer CONNECT_TIMEOUT = 10000;

    /**
     * OPEN_EULER: openeuler.
     */
    public static final String OPEN_EULER = "openeuler";
    /**
     * OPEN_GAUSS: opengauss.
     */
    public static final String OPEN_GAUSS = "opengauss";

    /**
     * openMind社区.
     */
    public static final String OPEN_MIND = "openmind";
    /**
     * OPEN_LOOK_ENG: openlookeng.
     */
    public static final String OPEN_LOOK_ENG = "openlookeng";
    /**
     * MIND_SPORE: mindspore.
     */
    public static final String MIND_SPORE = "mindspore";
    /**
     * INDIVIDUAL: individual.
     */
    public static final String INDIVIDUAL = "individual";
    /**
     * ORGANIZATION: organization.
     */
    public static final String ORGANIZATION = "organization";
    /**
     * ALL_ISSUE_CVE_STR: allIssueCveStr.
     */
    public static final String ALL_ISSUE_CVE_STR = "allIssueCveStr";
    /**
     * ALL_ISSUE_RESULT: allIssueResult.
     */
    public static final String ALL_ISSUE_RESULT = "allIssueResult";
    /**
     * 电话号码正则表达式，匹配以加号开头的数字.
     */
    public static final String PHONEREGEX = "^(\\+\\d{7,15})|(\\d{6,11})$";
    /**
     * 邮箱正则表达式，匹配常见邮箱格式.
     */
    public static final String EMAILREGEX = "^[A-Za-z0-9-._\\u4e00-\\u9fa5]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";

    /**
     * 用户名正则表达式，匹配特定用户名格式.
     */
    public static final String USERNAMEREGEX = "^[a-zA-Z][0-9a-zA-Z_-]{1,18}[0-9a-zA-Z]$";

    /**
     * openmind用户名规则.
     */
    public static final String OPEN_MIND_USERNAME_REGEX = "^[a-zA-Z]([-_.]([a-zA-Z0-9])|[a-zA-Z0-9])+$";

    /**
     * openmind用户名最小长度.
     */
    public static final int OPEN_MIND_USERNAME_MIN = 3;

    /**
     * openmind用户名最大长度.
     */
    public static final int OPEN_MIND_USERNAME_MAX = 40;

    /**
     * 昵称正则表达式，匹配特定昵称格式.
     */
    public static final String NICKNAMEREGEX =
            "^[a-zA-Z\\u4e00-\\u9fa5][0-9a-zA-Z_-\\u4e00-\\u9fa5]{1,18}[0-9a-zA-Z\\u4e00-\\u9fa5]$";

    /**
     * 公司名称正则表达式，匹配特定公司名称格式.
     */
    public static final String COMPANYNAMEREGEX =
            "^[0-9a-zA-Z\\u4e00-\\u9fa5][0-9a-zA-Z,\\.&\\(\\)（）\\s\\u4e00-\\u9fa5]{0,98}[0-9a-zA-Z\\.\\u4e00-\\u9fa5]$";

    /**
     * 敏感信息正则表达式，用于匹配包含密码、密钥、令牌或代码等敏感信息的字符串.
     */
    public static final String FULL_SENSITIVE_REG = "^.*(password|secret|token|code).*$";

    /**
     * 部分敏感信息正则表达式，用于匹配包含账号等部分敏感信息的字符串.
     */
    public static final String HALF_SENSITIVE_REG = "^.*(account).*$";

    /**
     * 电话号码替换正则表达式，用于替换电话号码中的部分数字.
     */
    public static final String PHONE_REPLACE_REG = "(^\\d{3})\\d.*(\\d{4})";

    /**
     * 邮箱替换正则表达式，用于替换邮箱地址中的字符.
     */
    public static final String EMAIL_REPLACE_REG = "(^\\w)[^@]*(@.*$)";


    /**
     * 默认过期秒数为60.
     */
    public static final String DEFAULT_EXPIRE_SECOND = "60";

    /**
     * OneID过期秒数为3000.
     */
    public static final String ONEID_EXPIRE_SECOND = "3000";

    /**
     * 认证中.
     */
    public static final String AUTHING = "authing";

    /**
     * OneID版本V1 - openEuler.
     */
    public static final String ONEID_VERSION_V1 = "openeuler";

    /**
     * OneID版本V2 - MindSpore.
     */
    public static final String ONEID_VERSION_V2 = "mindspore";


    /**
     * 成功.
     */
    public static final String SUCCESS = "success";

    /**
     * 邮件类型.
     */
    public static final String EMAIL_TYPE = "email";

    /**
     * 电话类型.
     */
    public static final String PHONE_TYPE = "phone";

    /**
     * 默认过期分钟数为1.
     */
    public static final String DEFAULT_EXPIRE_MINUTE = "1";

    /**
     * 默认验证码长度为6位.
     */
    public static final String DEFAULT_CODE_LENGTH = "6";


    /**
     * 注册渠道.
     */
    public static final String CHANNEL_REGISTER = "channel_register";

    /**
     * 密码注册渠道.
     */
    public static final String CHANNEL_REGISTER_BY_PASSWORD = "channel_register_by_password";

    /**
     * 登录渠道.
     */
    public static final String CHANNEL_LOGIN = "channel_login";

    /**
     * 重置密码渠道.
     */
    public static final String CHANNEL_RESET_PASSWORD = "channel_reset_password";


    /**
     * 默认随机字符串长度为32.
     */
    public static final int RANDOM_DEFAULT_LENGTH = 32;

    /**
     * 需要验证码验证.
     */
    public static final String NEED_CAPTCHA_VERIFICATION = "need_captcha_verification";

    /**
     * 需要验证码验证的次数限制为3次.
     */
    public static final String NEED_CAPTCHA_VERIFICATION_LIMIT = "3";

    /**
     * 登录错误次数限制为6次.
     */
    public static final String LOGIN_ERROR_LIMIT = "6";

    /**
     * LOGIN_COUNT: 登录计数.
     */
    public static final String LOGIN_COUNT = "loginCount";

    /**
     * 发送验证码标识.
     */
    public static final String SEND_CODE = "_sendCode_";

    /**
     * 注册后缀.
     */
    public static final String REGISTER_SUFFIX = "_register";

    /**
     * 重置密码后缀.
     */
    public static final String RESET_PASSWORD_SUFFIX = "_reset_password";

    /**
     * OneID Token键名.
     */
    public static final String ONEID_TOKEN_KEY = "Oneid-Token";

    /**
     * ID Token前缀.
     */
    public static final String ID_TOKEN_PREFIX = "idToken_";

    /**
     * 记录刚登录时的id-token，用于单会话登录.
     */
    public static final String REDIS_PREFIX_LOGIN_USER = "loginIdToken_";

    /**
     * 记录重置密码token的用户id.
     */
    public static final String REDIS_PREFIX_RESET_PASSWD = "resetPassWdToken_";

    /**
     * Token过期.
     */
    public static final String TOKEN_EXPIRES = "token expires";

    /**
     * Token YG值为0.
     */
    public static final int TOKEN_YG = 0;

    /**
     * Token Y_G_标识.
     */
    public static final String TOKEN_Y_G = "_Y_G_";

    /**
     * Token UT值为1.
     */
    public static final int TOKEN_UT = 1;

    /**
     * Token U_T_标识.
     */
    public static final String TOKEN_U_T = "_U_T_";


    /**
     * OneID用户合成路径.
     */
    public static final String ONEID_USER_C_PATH = "/composite-user";

    /**
     * OneID用户URD路径.
     */
    public static final String ONEID_USER_URD_PATH = "/composite-user/{account}";

    /**
     * OneID检查密码路径.
     */
    public static final String ONEID_CHECK_PASSWORD_PATH = "/auth/check-password/{account}";

    /**
     * OneID获取管理令牌路径.
     */
    public static final String ONEID_TOKEN_PATH = "/auth/get-management-token";

    /**
     * 不允许在照片中使用的字符集.
     */
    public static final String PHOTO_NOT_ALLOWED_CHARS = "\\,/,:,*,?,\",<,>,|";

    /**
     * 同意接受条款为0.
     */
    public static final String CONSENT_ACCEPT_TERM = "0";

    /**
     * 自动生成电子邮件后缀.
     */
    public static final String AUTO_GEN_EMAIL_SUFFIX = "@user.noreply.osinfra.cn";

    /**
     * 认证资源前缀长度为14.
     */
    public static final int AUTHING_RES_PREFIX_LENGTH = 14;

    /**
     * 合法authing的channel字符串序列.
     */
    public static final String AUTHING_CHANNELS = "CHANNEL_LOGIN,CHANNEL_REGISTER,CHANNEL_RESET_PASSWORD,"
            + "CHANNEL_VERIFY_EMAIL_LINK,CHANNEL_UPDATE_EMAIL,CHANNEL_BIND_EMAIL,CHANNEL_UNBIND_EMAIL,"
            + "CHANNEL_VERIFY_MFA,CHANNEL_UNLOCK_ACCOUNT,CHANNEL_COMPLETE_EMAIL,CHANNEL_DELETE_ACCOUNT,"
            + "CHANNEL_BIND_PHONE,CHANNEL_UNBIND_PHONE,CHANNEL_BIND_MFA,CHANNEL_VERIFY_MFA,CHANNEL_UNBIND_MFA,"
            + "CHANNEL_COMPLETE_PHONE,CHANNEL_IDENTITY_VERIFICATION,CHANNEL_DELETE_ACCOUNT";
}

