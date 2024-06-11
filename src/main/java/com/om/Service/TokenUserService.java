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

package com.om.Service;

import com.om.Vo.TokenUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TokenUserService {
    /**
     * 令牌用户名称.
     */
    @Value("${token.user.name}")
    private String tokenUserName;

    /**
     * 令牌用户密码.
     */
    @Value("${token.user.password}")
    private String tokenUserPassword;

    /**
     * 根据社区和用户名查找 TokenUser 对象.
     *
     * @param community 社区
     * @param name 用户名
     * @return TokenUser 对象
     */
    public TokenUser findByUsername(String community, String name) {
        if (!community.equalsIgnoreCase("openeuler")
                && !community.equalsIgnoreCase("opengauss")
                && !community.equalsIgnoreCase("mindspore")
                && !community.equalsIgnoreCase("openlookeng")) {
            return null;
        }

        if (name == null) {
            return null;
        }

        String userName = tokenUserName;
        if (name.equals(userName)) {
            return new TokenUser(community, userName, tokenUserPassword);
        }
        return null;
    }
}
