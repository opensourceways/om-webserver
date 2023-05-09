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
    @Value("${token.user.name}")
    private String tokenUserName;

    @Value("${token.user.password}")
    private String tokenUserPassword;

    public TokenUser findByUsername(String community, String name) {
        if (!community.equalsIgnoreCase("openeuler")
                && !community.equalsIgnoreCase("opengauss")
                && !community.equalsIgnoreCase("mindspore")
                && !community.equalsIgnoreCase("openlookeng")) {
            return null;
        }

        if (name == null) return null;

        String userName = tokenUserName;
        if (name.equals(userName)) {
            String password = tokenUserPassword;
            return new TokenUser(community, userName, password);
        }
        return null;
    }
}
