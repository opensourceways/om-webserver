package com.om.Modules;

public enum MessageCodeConfig {
    // success code message
    C0001("C0001", "code invalid or expired", "验证码无效或已过期"),
    C0002("C0002", "send code success", "验证码发送成功"),
    C0003("C0002", "unlink account success", ""),

    // fail code message
    E0001("E0001", "code invalid or expired", "验证码无效或已过期"),
    E0002("E0002", "code error", "验证码不正确"),
    E0003("E0003", "the phone has been bound to another account", "该手机号已被其它账户绑定"),
    E0004("E0004", "the mailbox has been bound to another account", "该邮箱已被其它账户绑定"),
    E0005("E0005", "no other login account,unable to unbind the account", "没有配置其他登录方式，不能解绑该账号"),
    E0006("E0006", "failed to unbind the third-party account", "解绑三方账号失败"),
    E0007("E0007", "failed to update base info", "更新失败"),
    E0008("E0008", "failed to send code", "验证码发送失败"),
    E0009("E0009", "sent one code within 1 minute", "一分钟之内已发送过验证码"),
    E00010("E00010", "failed to delete user", "注销用户失败"),
    E00011("E00011", "the old phone is not the phone bound to the user", "旧手机号非用户账号绑定的手机号"),
    E00012("E00012", "request error", "请求异常"),
    E00013("E00013", "the new mailbox is the same as the old mailbox", "新邮箱和旧邮箱一样"),
    E00014("E00014", "the new phone is the same as the old phone", "新手机号和旧手机号一样"),
    E00015("E00015", "the account has been bound phone ", "已绑定手机号"),
    E00016("E00016", "the account has been bound mailbox", "已绑定邮箱"),
    E00017("E00017", "failed to logout", "退出登录失败"),
    E00018("E00018", "username must be not empty", "用户名不能为空"),
    E00019("E00019", "username already exists", "用户名已存在"),
    E00020("E00020", "phone or mailbox must be not empty", "手机号或者邮箱不能为空"),
    E00021("E00021", "please enter the correct phone or mailbox", "请输入正确的手机号或者邮箱"),
    E00022("E00022", "the account is already registered", "该账号已注册"),
    E00023("E00023", "too frequent requests, please try again later", "请求过于频繁，请稍后再试"),
    E00024("E00024", "register failed", "注册失败"),
    E00025("E00025", "sent one code within 1 minute,please try again later", "该手机号 1 分钟内已发送过验证码，请稍后再试"),
    E00026("E00026", "code invalid or expired,please get it again", "验证码已失效，请重新获取验证码"),
    E00027("E00027", "failed to login", "登录失败"),
    E00028("E00028", "the number of sms messages sent from a single mobile number every day exceeds the upper limit", "手机号每天发送的验证次数超过上限"),
    E00029("E00029", "login and register use only", "仅登录和注册使用"),
    E00030("E00030", "failed limit reached,please try again later", "失败次数过多，请稍后重试"),
    E00031("E00031", "new mailbox is same as the old", "新邮箱与已绑定邮箱相同"),
    E00032("E00032", "new phone number is same as the old", "新手机号与已绑定手机号相同"),
    E00033("E00033", "username is unique and cannot be modified", "用户名唯一，不可修改"),
    E00034("E00034", "username not exists", "用户不存在"),
    ;

    private String code;
    private String msgEn;
    private String msgZh;

    MessageCodeConfig(String code, String msgEn, String msgZh) {
        this.code = code;
        this.msgEn = msgEn;
        this.msgZh = msgZh;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMsgEn() {
        return msgEn;
    }

    public void setMsgEn(String msgEn) {
        this.msgEn = msgEn;
    }

    public String getMsgZh() {
        return msgZh;
    }

    public void setMsgZh(String msgZh) {
        this.msgZh = msgZh;
    }
}
