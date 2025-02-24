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
     * openMind社区.
     */
    public static final String OPEN_MIND = "openmind";

    /**
     * openUBMC社区.
     */
    public static final String OPEN_UBMC = "openubmc";

    /**
     * MIND_SPORE: mindspore.
     */
    public static final String MIND_SPORE = "mindspore";

    /**
     * openMind.
     */
    public static final String MODEL_FOUNDRY = "modelfoundry";

    /**
     * 电话号码正则表达式，匹配以加号开头的数字.
     */
    public static final String PHONEREGEX = "^(\\+\\d{7,15})|(\\d{6,11})$";
    /**
     * 邮箱正则表达式，匹配常见邮箱格式.
     */
    public static final String EMAILREGEX = "^[A-Za-z0-9-._\\u4e00-\\u9fa5]{1,40}"
            + "@[a-zA-Z0-9_-]{1,20}(\\.[a-zA-Z0-9_-]{1,20}){1,10}$";

    /**
     * 用户名正则表达式，匹配特定用户名格式.
     */
    public static final String USERNAMEREGEX = "^[a-zA-Z][0-9a-zA-Z_-]{1,18}[0-9a-zA-Z]$";

    /**
     * openmind用户名规则.
     */
    public static final String OPEN_MIND_USERNAME_REGEX = "^[a-zA-Z]([-_.]([a-zA-Z0-9])|[a-zA-Z0-9])+$";

    /**
     * 发送验证码标识.
     */
    public static final String SEND_CODE_V1 = "_sendcode";

    /**
     * 字母或数字.
     */
    public static final String NORMAL_STR_REGEX = "[a-zA-Z0-9]+";

    /**
     * openmind用户名最小长度.
     */
    public static final int OPEN_MIND_USERNAME_MIN = 3;

    /**
     * openmind用户名最大长度.
     */
    public static final int OPEN_MIND_USERNAME_MAX = 40;

    /**
     * 默认过期秒数为60.
     */
    public static final String DEFAULT_EXPIRE_SECOND = "60";


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
     * LOGIN_COUNT: 绑定计数.
     */
    public static final String BIND_FAILED_COUNT = "bindFailedCount";

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
     * authing管理面token.
     */
    public static final String REDIS_KEY_AUTH_MANAGER_TOKEN = "authingManagerToken";

    /**
     * 敏感信息检查token缓存.
     */
    public static final String REDIS_KEY_MODERATOR_TOKEN = "moderatorAuthToken";

    /**
     * 敏感信息检查中文语言类型
     */
    public static final String MODERATOR_V3_LANGUAGE_ZH = "zh";

    /**
     * 敏感文本信息检查昵称事件类型
     */
    public static final String MODERATOR_V3_EVENT_TYPE_NICKNAME = "nickname";

    /**
     * Token过期.
     */
    public static final String TOKEN_EXPIRES = "token expires";

    /**
     * Token YG值为0.
     */
    public static final int TOKEN_YG = 0;

    /**
     * Token UT值为1.
     */
    public static final int TOKEN_UT = 1;

    /**
     * Token U_T_标识.
     */
    public static final String TOKEN_U_T = "_U_T_";


    /**
     * 不允许在照片中使用的字符集.
     */
    public static final String PHOTO_NOT_ALLOWED_CHARS = "\\,/,:,*,?,\",<,>,|";

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
            + "CHANNEL_COMPLETE_PHONE,CHANNEL_IDENTITY_VERIFICATION,CHANNEL_DELETE_ACCOUNT,CHANNEL_MERGE_USER";
}
