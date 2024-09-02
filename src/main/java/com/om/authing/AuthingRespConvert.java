/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.authing;

import com.om.modules.MessageCodeConfig;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 限制Authing的错误信息返回.
 */
public final class AuthingRespConvert {
    private AuthingRespConvert() {
        throw new AssertionError("Utility class. Not intended for instantiation.");
    }

    /**
     * 日志记录.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthingRespConvert.class);

    /**
     * 字段冲突，表明邮箱已经被别人绑定.
     */
    private static final String FIELD_CONFLICT = "duplicate key value violates unique";

    /**
     * 只能能对外展示的Authing错误信息.
     */
    private static final Map<Integer, String> API_CODE_MAP = Collections.unmodifiableMap(
            new HashMap<>() {
                {
                    put(500, "验证码不正确");
                    put(1000, "系统繁忙，请稍后再试");
                    put(1001, "无权限执行此操作");
                    put(1576, "无权限登录此应用，请联系管理员");
                    put(1639, "首次登录重置密码（不需要验证旧密码）");
                    put(1640, "触发联邦认证询问身份绑定，只允许绑定现有账号");
                    put(1641, "触发联邦认证询问身份绑定，允许绑定现有账号和创建新账号");
                    put(1642, "登录信息补全");
                    put(1643, "用户自主解锁");
                    put(1699, "提前终止认证后流程，返回登录界面");
                    put(1700, "未上传人脸识别的照片");
                    put(1701, "人脸对比时，未上传需要对比的图片");
                    put(1702, "人脸校验错误");
                    put(1703, "未绑定邮箱或手机号，无法绑定人脸");
                    put(1704, "绑定人脸时，手机验证失败");
                    put(1705, "绑定人脸时，邮箱验证失败");
                    put(1706, "人脸已被绑定");
                    put(1707, "绑定人脸失败");
                    put(2000, "须要图形验证码或图形验证码错误");
                    put(2001, "验证码已失效，请重新获取验证码");
                    put(2003, "注册或登陆时邮箱不正确");
                    put(2004, "用户不存在");
                    put(2005, "用户已锁定");
                    put(2006, "密码错误");
                    put(2020, "尚未登录，无权限访问此请求");
                    put(2026, "用户已存在，请直接登录");
                    put(2028, "请提供正确的手机号或邮箱");
                    put(2029, "密码长度不能少于 6 位");
                    put(2031, "应用已禁止注册用户");
                    put(2032, "注册时需要密码");
                    put(2034, "用户名已存在");
                    put(2035, "手机号已绑定");
                    put(2037, "填写的旧邮箱与实际邮箱不匹配");
                    put(2038, "填写的旧手机与实际手机不匹配");
                    put(2058, "强制重置密码（需要验证旧密码）");
                    put(2059, "密码重复设置");
                    put(2080, "该邮箱 1 分钟内已发送过验证码，请稍后再试");
                    put(2100, "注册过于频繁，请稍候再试");
                    put(2200, "该邮箱已被绑定");
                    put(2203, "原始密码错误");
                    put(2204, "邮箱格式不正确");
                    put(2206, "登录信息已过期, 需重新登录");
                    put(2207, "登录信息有误, 需重新登录");
                    put(2229, "新邮箱和旧邮箱一样");
                    put(2230, "新手机号和旧手机号一样");
                    put(2300, "验证码过期");
                    put(2333, "用户名或密码错误");
                    put(2334, "AD 用户验证失败");
                    put(2338, "AD 账号或密码错误");
                    put(2339, "AD 账户限制阻止了用户的登录");
                    put(2340, "AD 登录时间限制违规");
                    put(2341, "AD 不允许登录到此计算机");
                    put(2342, "AD 密码已过期");
                    put(2343, "AD 账号已被禁用或锁定");
                    put(2344, "AD 账号已过期，请联系管理员");
                    put(2345, "AD 无法使用此密码进行登录，请修改密码或联系管理员");
                    put(2346, "AD 当前账户已被锁定，请自助解锁或联系管理员");
                    put(2347, "AD 操作失败，非子叶节点");
                    put(4004, "该手机号 1 分钟内已发送过验证码，请稍后再试");
                    put(2120008, "用户已停用或不是此租户成员");
                    put(2130010, "用户无权限登录此租户");
                    put(3103, "发送邮件错误，未知错误");
                }
            }
    );

    /**
     * 转换Authing错误信息.
     *
     * @param resObj Authing的rest接口返回值
     * @param msg    指定默认错误信息
     * @return 转换后信息
     */
    public static String convertMsg(JSONObject resObj, String msg) {
        String conMsg = MessageCodeConfig.E00012.getMsgZh();
        if (StringUtils.isNotBlank(msg)) {
            conMsg = msg;
        }
        if (resObj == null) {
            return conMsg;
        }
        String resObjMsg = resObj.getString("message");
        if (resObj.has("apiCode") && API_CODE_MAP.containsKey(resObj.getInt("apiCode"))) {
            conMsg = resObjMsg;
        } else {
            LOGGER.warn("Authing err message: {}", resObjMsg);
        }
        return conMsg;
    }

    /**
     * 绑定邮箱错误信息转化.
     *
     * @param msg 原始信息
     * @return 转化结果
     */
    public static String convertBindEmailMsg(String msg) {
        String conMsg = msg;
        if (StringUtils.isBlank(msg)) {
            return conMsg;
        }
        if (msg.startsWith(FIELD_CONFLICT)) {
            conMsg = MessageCodeConfig.E0004.getMsgZh();
        }
        return conMsg;
    }
}
