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

package com.om.Service.inter;

import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface UserCenterServiceInter {
    ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess);

    ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity login(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity personalCenterUserInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity deleteUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);
}
