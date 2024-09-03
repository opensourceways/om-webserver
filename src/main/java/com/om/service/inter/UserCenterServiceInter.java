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

package com.om.service.inter;

import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Map;

public interface UserCenterServiceInter {
    /**
     * 验证码登录方法.
     *
     * @param servletRequest HTTP请求对象
     * @return ResponseEntity 响应实体
     */
    ResponseEntity captchaLogin(HttpServletRequest servletRequest);

    /**
     * 注册用户的方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    /**
     * 发送验证码.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    ResponseEntity sendCodeV3(HttpServletRequest servletRequest,
                              HttpServletResponse servletResponse, boolean isSuccess);

    /**
     * 检查账户是否存在的方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    /**
     * 登录方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    ResponseEntity login(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess);

    /**
     * 个人中心用户信息方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity personalCenterUserInfo(HttpServletRequest servletRequest,
                                          HttpServletResponse servletResponse, String token);

    /**
     * 注销方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    /**
     * 刷新用户信息的方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    /**
     * 删除用户方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity deleteUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    /**
     * 更新用户基本信息方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @param map             用户信息映射
     * @return ResponseEntity 响应实体
     */
    ResponseEntity updateUserBaseInfo(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse, String token, Map<String, Object> map);

    /**
     * 更新照片方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @param file            上传的文件
     * @return ResponseEntity 响应实体
     */
    ResponseEntity updatePhoto(HttpServletRequest servletRequest,
                               HttpServletResponse servletResponse, String token, MultipartFile file);

    /**
     * 发送解绑验证码方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param isSuccess       是否成功标识
     * @return ResponseEntity 响应实体
     */
    ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest,
                                  HttpServletResponse servletResponse, boolean isSuccess);

    /**
     * 更新账户信息方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity updateAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    /**
     * 解绑账户方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity unbindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    /**
     * 绑定账户方法.
     *
     * @param servletRequest  HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @param token           令牌
     * @return ResponseEntity 响应实体
     */
    ResponseEntity bindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    /**
     * 获取公钥方法.
     *
     * @return ResponseEntity 响应实体
     */
    ResponseEntity getPublicKey();

    /**
     * 重置密码验证方法.
     *
     * @param servletRequest HTTP请求对象
     * @return ResponseEntity 响应实体
     */
    ResponseEntity resetPwdVerify(HttpServletRequest servletRequest);

    /**
     * 重置密码方法.
     *
     * @param servletRequest HTTP请求对象
     * @param servletResponse HTTP响应对象
     * @return ResponseEntity 响应实体
     */
    ResponseEntity resetPwd(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    /**
     * 应用验证方法.
     *
     * @param appId    应用ID
     * @param redirect 重定向URL
     * @return ResponseEntity 响应实体
     */
    ResponseEntity appVerify(String appId, String redirect);
}
