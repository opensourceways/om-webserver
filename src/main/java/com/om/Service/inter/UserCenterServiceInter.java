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

import com.om.provider.oauth2.OidcProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

public interface UserCenterServiceInter {
    ResponseEntity register(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity sendCodeV3(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess);

    ResponseEntity accountExists(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity login(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity personalCenterUserInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity refreshUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity deleteUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity updateUserBaseInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token, Map<String, Object> map);

    ResponseEntity updatePhoto(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token, MultipartFile file);

    ResponseEntity sendCodeUnbind(HttpServletRequest servletRequest, HttpServletResponse servletResponse, boolean isSuccess);

    ResponseEntity updateAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity unbindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity bindAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String token);

    ResponseEntity providerCallback(HttpServletRequest servletRequest, HttpServletResponse servletResponse, OidcProvider oidcProvider);

    ResponseEntity providerLogin(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity getUserIdentity(HttpServletRequest servletRequest);

    ResponseEntity linkToExistUser(HttpServletRequest servletRequest, HttpServletResponse servletResponse);

    ResponseEntity userLink(HttpServletRequest request, HttpServletResponse response);

    ResponseEntity userUnlink(HttpServletRequest request, HttpServletResponse response);
}
