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

package com.om.modules;

import java.util.HashMap;
import java.util.Map;

/**
 * 消息代码配置枚举类.
 */
public enum MessageCodeConfig {
    // success code message
    /**
     * 成功代码消息：一般成功.
     */
    S0001("S0001", "Success", "成功"),

    // fail code message
    /**
     * 错误代码 E0001: 验证码无效或已过期.
     */
    E0001("E0001", "Code invalid or expired", "验证码无效或已过期"),
    /**
     * 错误代码 E0002: 验证码不正确.
     */
    E0002("E0002", "Wrong code. Try again.", "验证码不正确"),
    /**
     * 错误代码 E0003: 该手机号已被其它账户绑定.
     */
    E0003("E0003", "The phone has been bound to another account", "该手机号已被其它账户绑定"),
    /**
     * 错误代码 E0004: 该邮箱已被其它账户绑定.
     */
    E0004("E0004", "The email has been bound to another account", "该邮箱已被其它账户绑定"),
    /**
     * 错误代码 E0005: 没有配置其他登录方式，不能解绑该账号.
     */
    E0005("E0005", "No other login account. Unable to unbind the account", "没有配置其他登录方式，不能解绑该账号"),
    /**
     * 错误代码 E0006: 解绑三方账号失败.
     */
    E0006("E0006", "Failed to unbind the third-party account", "解绑三方账号失败"),
    /**
     * 错误代码 E0007: 更新失败.
     */
    E0007("E0007", "Failed to update user info", "更新失败"),
    /**
     * 错误代码 E0008: 验证码发送失败.
     */
    E0008("E0008", "Failed to send code", "验证码发送失败"),
    /**
     * 错误代码 E0009: 一分钟之内已发送过验证码.
     */
    E0009("E0009", "Verification code has been sent within a minute", "一分钟之内已发送过验证码"),
    /**
     * 错误代码 E00010: 注销用户失败.
     */
    E00010("E00010", "Failed to delete user", "注销用户失败"),
    /**
     * 错误代码 E00010: 旧手机号非用户账号绑定的手机号.
     */
    E00011("E00011", "The old phone is not the phone bound to the user", "旧手机号非用户账号绑定的手机号"),
    /**
     * 错误代码 E00012: 请求异常.
     */
    E00012("E00012", "Request Error", "请求异常"),
    /**
     * 错误代码 E00013: 新邮箱和旧邮箱一样.
     */
    E00013("E00013", "The new email is the same as the old email", "新邮箱和旧邮箱一样"),
    /**
     * 错误代码 E00014: 新手机号和旧手机号一样.
     */
    E00014("E00014", "The new phone is the same as the old phone", "新手机号和旧手机号一样"),
    /**
     * 错误代码 E00015: 已经绑定了手机号.
     */
    E00015("E00015", "The account has been bound phone ", "已经绑定了手机号"),
    /**
     * 错误代码 E00016: 已经绑定了邮箱.
     */
    E00016("E00016", "The account has been bound email", "已经绑定了邮箱"),
    /**
     * 错误代码 E00017: 退出登录失败.
     */
    E00017("E00017", "Failed to logout", "退出登录失败"),
    /**
     * 错误代码 E00018: 用户名不能为空.
     */
    E00018("E00018", "Username must be not empty", "用户名不能为空"),
    /**
     * 错误代码 E00019: 用户名已存在.
     */
    E00019("E00019", "Username is illegal", "用户名不合法"),
    /**
     * 错误代码 E00020: 手机号或者邮箱不能为空.
     */
    E00020("E00020", "Phone or email must be not empty", "手机号或者邮箱不能为空"),
    /**
     * 错误代码 E00021: 请输入正确的手机号或者邮箱.
     */
    E00021("E00021", "Please enter the correct phone or email", "请输入正确的手机号或者邮箱"),
    /**
     * 错误代码 E00022: 该账号已注册.
     */
    E00022("E00022", "This account is already registered", "该账号已注册"),
    /**
     * 错误代码 E00023: 请求过于频繁，请稍后再试.
     */
    E00023("E00023", "The request is too frequent. Please try again later", "请求过于频繁，请稍后再试"),
    /**
     * 错误代码 E00024: 注册失败.
     */
    E00024("E00024", "Failed to register", "注册失败"),
    /**
     * 错误代码 E00025: 该手机号 1 分钟内已发送过验证码，请稍后再试.
     */
    E00025("E00025", "Verification code has been sent within a minute.Please try again later",
            "该手机号 1 分钟内已发送过验证码，请稍后再试"),
    /**
     * 错误代码 E00026: 验证码已失效，请重新获取验证码.
     */
    E00026("E00026", "Verification code invalid or expired. Please get it again",
            "验证码已失效，请重新获取验证码"),
    /**
     * 错误代码 E00027: 登录失败.
     */
    E00027("E00027", "Failed to login", "登录失败"),
    /**
     * 错误代码 E00028: 手机号每天发送的验证次数超过上限.
     */
    E00028("E00028", "The number of verifications sent by the mobile phone number per day exceeds the upper limit",
            "手机号每天发送的验证次数超过上限"),
    /**
     * 错误代码 E00029: 仅登录、注册和重置密码使用.
     */
    E00029("E00029", "For login, registration adn reset password use only", "仅登录、注册和重置密码使用"),
    /**
     * 错误代码 E00030: 失败次数过多，请稍后重试.
     */
    E00030("E00030", "Too many failures, Please try again in 1 hour", "失败次数过多，请1小时后重试"),
    /**
     * 错误代码 E00031: 新邮箱与已绑定邮箱相同.
     */
    E00031("E00031", "The new email is the same as the old", "新邮箱与已绑定邮箱相同"),
    /**
     * 错误代码 E00032: 新手机号与已绑定手机号相同.
     */
    E00032("E00032", "The new phone number is the same as the old", "新手机号与已绑定手机号相同"),
    /**
     * 错误代码 E00033: 用户名唯一，不可修改.
     */
    E00033("E00033", "Username is unique and cannot be modified", "用户名唯一，不可修改"),
    /**
     * 错误代码 E00034: 用户不存在.
     */
    E00034("E00034", "User doesn't exist", "用户不存在"),
    /**
     * 错误代码 E00035: 回调地址与配置不符.
     */
    E00035("E00035", "The redirect uri does not match the configuration", "回调地址与配置不符"),
    /**
     * 错误代码 E00036: 请指定应用的id、secret、host.
     */
    E00036("E00036", "App not found. Please check the parameter", "请指定应用的id、secret、host"),
    /**
     * 错误代码 E00037: 授权失败.
     */
    E00037("E00037", "Authorization failed", "授权失败"),
    /**
     * 错误代码 E00038: 请先绑定邮箱.
     */
    E00038("E00038", "Please bind the email first", "请先绑定邮箱"),
    /**
     * 错误代码 E00039: 邮箱不能为空.
     */
    E00039("E00039", "Email must be not empty", "邮箱不能为空"),
    /**
     * 错误代码 E00040: 请输入正确的邮箱.
     */
    E00040("E00040", "Please enter the correct email", "请输入正确的邮箱"),
    /**
     * 错误代码 E00041: 请输入3到20个字符。只能由字母、数字、下划线(_)或者连字符(-)组成。必须以字母开头，不能以下划线(_)结尾.
     */
    E00041("E00041", "Contain 3 to 20 characters. include only letters, digits, underscores (_) and hyphen (-)."
            + " It must start with a letter and cannot end with underscore (_)",
            "请输入3到20个字符。只能由字母、数字、下划线(_)或者连字符(-)组成。必须以字母开头，不能以下划线(_)结尾"),
    /**
     * 错误代码 E00042: 应用未找到.
     */
    E00042("E00042", "App not found", "应用未找到"),
    /**
     * 错误代码 E00043: 请输入正确的手机号码.
     */
    E00043("E00043", "Please enter the correct phone number", "请输入正确的手机号码"),
    /**
     * 错误代码 E00044: 请输入正确的公司名.
     */
    E00044("E00044", "Please enter the correct company name", "请输入正确的公司名"),
    /**
     * 错误代码 E00045: 请输入3到20个字符。昵称只能由字母、数字、汉字、下划线(_)或者连字符(-)组成。必须以字母或者汉字开头，不能以下划线(_)结尾.
     */
    E00045("E00045", "Contain 3 to 20 characters. nickname include only letters, digits, Chinese, "
            + "underscores (_) and hyphen (-). Must start with a letter or Chinese. cannot end with underscore (_)",
            "请输入3到20个字符。昵称只能由字母、数字、汉字、下划线(_)或者连字符(-)组成。必须以字母或者汉字开头，不能以下划线(_)结尾"),
    /**
     * 错误代码 E00046: 请输入2到100个字符。公司只能由字母、数字、汉字、括号或者点(.)、逗号(,)、&组成。必须以字母、数字或者汉字开头，不能以括号、逗号(,)和&结尾.
     */
    E00046("E00046", "Contain 2 to 100 characters. company include only letters, digits, Chinese, parentheses,"
            + " point (.), comma (,) and &. Must start with a letter, digits or Chinese."
            + " cannot end with parentheses, comma (,) and &",
            "请输入2到100个字符。公司只能由字母、数字、汉字、括号或者点(.)、逗号(,)、&组成。必须以字母、数字或者汉字开头，不能以括号、逗号(,)和&结尾"),
    /**
     * 错误代码 E00047: 应用不存在.
     */
    E00047("E00047", "App not found", "应用不存在"),
    /**
     * 错误代码 E00048: 服务异常.
     */
    E00048("E00048", "Internal Server Error", "服务错误"),
    /**
     * 错误代码 E00049: 该邮箱 1 分钟内已发送过验证码，请稍后再试.
     */
    E00049("E00049", "Verification code has been sent within a minute. Please try again later",
            "该邮箱 1 分钟内已发送过验证码，请稍后再试"),
    /**
     * 错误代码 E00050: 该手机号 24 小时内已发送过验证码超过最大上限，请稍后尝试.
     */
    E00050("E00050", "The verification code sent by this phone number within 24 hours exceeds the maximum limit",
            "该手机号 24 小时内已发送过验证码超过最大上限，请稍后尝试"),
    /**
     * 错误代码 E00051: 不支持的加密类型.
     */
    E00051("E00051", "Unsupported encryption type", "不支持的加密类型"),
    /**
     * 错误代码 E00052: 账号或密码有误.
     */
    E00052("E00052", "Invalid account or password.", "账号或密码有误"),
    /**
     * 错误代码 E00053: 密码修改失败.
     */
    E00053("E00053", "Fail to modify password.", "密码修改失败"),
    /**
     * 错误代码 E00054: 密码不符合当前密码强度.
     */
    E00054("E00054", "Invalid password.", "密码不符合当前密码强度"),
    /**
     * 错误代码 E00055: 原始密码不正确.
     */
    E00055("E00055", "Invalid old password", "原始密码不正确"),
    /**
     * 错误代码 E00056: 校验失败.
     */
    E00056("E00056", "Token invalid or expired", "Token 校验失败"),
    /**
     * 错误代码 E00057: 用户已存在，请直接登录.
     */
    E00057("E00057", "User already exists, log in directly", "用户已存在，请直接登录"),
    /**
     * 错误代码 E00058: 请使用至少 6 位字符作为密码，须包含英文、数字与符号中的两种.
     */
    E00058("E00058", "Must be 6 to 20 characters long. Must contain at least 3 of the following character types:"
            + " letters, digits, and special characters", "请使用至少 6 位字符作为密码，须包含英文、数字与符号中的两种"),
    /**
     * 错误代码 E00059: 新密码不能与原密码相同.
     */
    E00059("E00059", "Password needs to be different from previous one", "新密码不能与原密码相同"),
    /**
     * 错误代码 E00060: 重置密码失败.
     */
    E00060("E00060", "Reset password fail", "重置密码失败"),
    /**
     * 错误代码 E00061: 密码未设置.
     */
    E00061("E00061", "Password is not set", "密码未设置"),
    /**
     * 错误代码 E00062: 未同意隐私政策.
     */
    E00062("E00062", "Not agree to accept term", "未同意隐私政策"),
    /**
     * 错误代码 E00063: 页面或资源不存在.
     */
    E00063("E00063", "Page does not exist.", "页面或资源不存在"),
    /**
     * 错误代码 E00064: 仅支持ID、用户名、gitee用户名、github用户名单一参数查找用户.
     */
    E00064("E00064", "Only ID, username, gitee username,"
            + " and github username are supported for single parameter search of users",
            "仅支持ID、用户名、gitee用户名、github用户名单一参数查找用户"),

    /**
     * Error code E00065: Request exceeds the limit.
     * Chinese: 请求超过限制.
     */
    E00065("E00065", "Request exceeds the limit. Please try again later", "请求过于频繁，请稍后再次尝试"),

    /**
     * openmind用户名不符合要求.
     */
    E00066("E00066", "Contain 3 to 40 characters. include only letters, digits or special characters _-. ."
            + " Must start with a letter, cannot end with a special character, "
            + "and cannot contain two or more consecutive special characters",
            "请输入3到40个字符。只能由字母、数字或特殊字符_-.组成。必须以字母开头，不能以特殊字符结尾，且不能包含两个及以上连续特殊字符"),
    /**
     * 错误代码 E00067: 请先绑定手机号.
     */
    E00067("E00067", "Please bind the phone number first", "请先绑定手机号"),

    /**
     * 仅支持中国区手机号.
     */
    E00068("E00068", "Only supports mobile phone numbers in China", "仅支持中国区手机号"),

    /**
     * 错误代码 E00069: 账号异常，不支持绑定绑定已有账号.
     */
    E00069("E00069", "The account is abnormal and binding to existing accounts is not supported",
                   "账号异常，不支持绑定已有账号"),

    /**
     * 错误代码 E00070: 该账号已绑定其他三方账号，请解绑后重试.
     */
    E00070("E00070", "This account has been bound to other third-party accounts. Please unbind and try again",
            "该账号已绑定其他三方账号，请解绑后重试"),

    /**
     * 错误代码 E00071: 绑定已有账号失败.
     */
    E00071("E00071", "Failed to bind existing account", "绑定已有账号失败");

    /**
     * 消息代码.
     */
    private String code;

    /**
     * 英文消息.
     */
    private String msgEn;

    /**
     * 中文消息.
     */
    private String msgZh;


    MessageCodeConfig(String code, String msgEn, String msgZh) {
        this.code = code;
        this.msgEn = msgEn;
        this.msgZh = msgZh;
    }

    /**
     * 获取消息代码.
     *
     * @return 消息代码
     */
    public String getCode() {
        return code;
    }

    /**
     * 获取英文消息.
     *
     * @return 英文消息
     */
    public String getMsgEn() {
        return msgEn;
    }

    /**
     * 获取中文消息.
     *
     * @return 中文消息
     */
    public String getMsgZh() {
        return msgZh;
    }

    /**
     * 获取错误代码映射.
     *
     * @return 包含错误代码配置对象的映射
     */
    public static Map<String, MessageCodeConfig> getErrorCode() {
        HashMap<String, MessageCodeConfig> map = new HashMap<>();
        map.put("验证码已失效", E0001);
        map.put("验证码无效或已过期", E0001);
        map.put("验证码不正确", E0002);
        map.put("该手机号已被绑定", E0003);
        map.put("该手机号已被其它账户绑定", E0003);
        map.put("该邮箱已被其它账户绑定", E0004);
        map.put("该邮箱已被绑定", E0004);
        map.put("Duplicate entry", E0004);
        map.put("没有配置其他登录方式", E0005);
        map.put("解绑三方账号失败", E0006);
        map.put("更新失败", E0007);
        map.put("验证码发送失败", E0008);
        map.put("一分钟之内已发送过验证码", E0009);
        map.put("注销用户失败", E00010);
        map.put("旧手机号非用户账号绑定的手机号", E00011);
        map.put("请求异常", E00012);
        map.put("新邮箱和旧邮箱一样", E00013);
        map.put("新手机号和旧手机号一样", E00014);
        map.put("已经绑定了手机号", E00015);
        map.put("已经绑定了邮箱", E00016);
        map.put("退出登录失败", E00017);
        map.put("用户名不能为空", E00018);
        map.put("用户名已存在", E00019);
        map.put("手机号或者邮箱不能为空", E00020);
        map.put("请输入正确的手机号或者邮箱", E00021);
        map.put("该账号已注册", E00022);
        map.put("请求过于频繁", E00023);
        map.put("注册失败", E00024);
        map.put("该手机号 1 分钟内已发送过验证码", E00025);
        map.put("验证码已失效，请重新获取验证码", E00026);
        map.put("登录失败", E00027);
        map.put("mobile number every day exceeds the upper limit", E00028);
        map.put("手机号每天发送的验证次数超过上限", E00028);
        map.put("仅登录、注册和重置密码使用", E00029);
        map.put("失败次数过多，请1小时后重试", E00030);
        map.put("新邮箱与已绑定邮箱相同", E00031);
        map.put("新手机号与已绑定手机号相同", E00032);
        map.put("用户名唯一，不可修改", E00033);
        map.put("用户不存在", E00034);
        map.put("回调地址与配置不符", E00035);
        map.put("请指定应用的id、secret、host", E00036);
        map.put("授权失败", E00037);
        map.put("请先绑定邮箱", E00038);
        map.put("邮箱不能为空", E00039);
        map.put("请输入正确的邮箱", E00040);
        map.put("请输入3到20个字符。只能由字母、数字或者下划线(_)组成。必须以字母开头，不能以下划线(_)结尾", E00041);
        map.put("应用未找到", E00042);
        map.put("请输入正确的手机号码", E00043);
        map.put("请输入正确的公司名", E00044);
        map.put("请输入3到20个字符。昵称只能由字母、数字、汉字或者下划线(_)组成。必须以字母或者汉字开头，不能以下划线(_)结尾", E00045);
        map.put("请输入2到100个字符。公司只能由字母、数字、汉字、括号或者点(.)、逗号(,)、&组成。必须以字母、数字或者汉字开头，不能以括号、逗号(,)和&结尾", E00046);
        map.put("应用不存在", E00047);
        map.put("服务错误", E00048);
        map.put("该邮箱 1 分钟内已发送过验证码", E00049);
        map.put("已发送过验证码超过最大上限", E00050);
        map.put("不支持的加密类型", E00051);
        map.put("passwordEncryptType must be a valid enum value", E00051);
        map.put("账号或密码有误", E00052);
        map.put("解密密码失败", E00052);
        map.put("Execute query failed: Password is not valid", E00052);
        map.put("密码不允许为空", E00052);
        map.put("密码修改失败", E00053);
        map.put("密码不符合当前密码强度", E00054);
        map.put("原始密码不正确", E00055);
        map.put("Token 校验失败", E00056);
        map.put("用户已存在", E00057);
        map.put("请使用至少 6 位字符作为密码，须包含英文、数字与符号中的两种", E00058);
        map.put("Password is not correct", E00052);
        map.put("Password needs to be different from previous", E00059);
        map.put("invalid password", E00058);
        map.put("reset password token expire", E00056);
        map.put("reset password fail", E00060);
        map.put("User not exist", E00034);
        map.put("No password is set", E00052);
        map.put("Account not exist", E00052);
        map.put("已绑定邮箱", E00016);
        map.put("[openMind] username invalid", E00066);
        map.put("Please bind the phone number first", E00067);
        map.put("Only supports mobile phone numbers in China", E00068);

        return map;
    }
}
