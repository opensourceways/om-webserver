/*
 *Copyright © 2018 anji-plus
 *安吉加加信息技术有限公司
 *http://www.anji-plus.com
 *All rights reserved.
 */
package com.anji.captcha.Controller;

import com.anji.captcha.model.common.ResponseModel;
import com.anji.captcha.model.vo.CaptchaVO;
import com.anji.captcha.service.CaptchaService;
import com.anji.captcha.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 用于处理验证码相关的请求和逻辑.
 */
@RestController("updatedCaptchaController")
@RequestMapping("/captcha")
public class CaptchaController {
    /**
     * 用于生成和验证验证码的服务对象.
     */
    @Autowired
    private CaptchaService captchaService;

    /**
     * 获取验证码信息.
     *
     * @param data    请求体中的 CaptchaVO 对象，包含验证码相关数据
     * @param request HTTP 请求对象
     * @return 返回 ResponseModel 包含处理结果信息
     */
    @PostMapping("/get")
    public ResponseModel get(@RequestBody CaptchaVO data, HttpServletRequest request) {
        data.setBrowserInfo(getRemoteId(request));
        return captchaService.get(data);
    }

    /**
     * 处理验证码检查逻辑，验证传入的验证码信息.
     *
     * @param data    请求体中的 CaptchaVO 对象，包含待检查的验证码信息
     * @param request HTTP 请求对象
     * @return 返回 ResponseModel 包含验证码检查结果信息
     */
    @PostMapping("/check")
    public ResponseModel check(@RequestBody CaptchaVO data, HttpServletRequest request) {
        data.setBrowserInfo(getRemoteId(request));
        return captchaService.check(data);
    }

    /**
     * 从 HttpServletRequest 中获取远程主机的 IP 地址或者主机名.
     *
     * @param request HTTP 请求对象
     * @return 返回远程主机的 IP 地址或者主机名
     */
    public static String getRemoteId(HttpServletRequest request) {
        String xfwd = request.getHeader("X-Forwarded-For");
        String ip = getRemoteIpFromXfwd(xfwd);
        String ua = request.getHeader("user-agent");
        if (StringUtils.isNotBlank(ip)) {
            return ip + ua;
        }
        return request.getRemoteAddr() + ua;
    }

    /**
     * 从 X-Forwarded-For 头部信息中获取远程客户端 IP 地址.
     *
     * @param xfwd 包含 X-Forwarded-For 头部信息的字符串
     * @return 返回解析后的远程客户端 IP 地址
     */
    private static String getRemoteIpFromXfwd(String xfwd) {
        if (StringUtils.isNotBlank(xfwd)) {
            String[] ipList = xfwd.split(",");
            return StringUtils.trim(ipList[0]);
        }
        return null;
    }
}
