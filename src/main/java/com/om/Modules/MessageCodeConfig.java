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
