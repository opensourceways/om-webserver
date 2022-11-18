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

import com.om.Modules.*;
import com.om.Vo.TokenUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenUserService {
    @Autowired
    private openEuler openeuler;
    @Autowired
    private openGauss opengauss;
    @Autowired
    private openLookeng openlookeng;
    @Autowired
    private mindSpore mindspore;

    public TokenUser findByUsername(String community, String name) {
        openComObject communityObj;
        switch (community.toLowerCase()) {
            case "openeuler":
                communityObj = openeuler;
                break;
            case "opengauss":
                communityObj = opengauss;
                break;
            case "openlookeng":
                communityObj = openlookeng;
                break;
            case "mindspore":
                communityObj = mindspore;
                break;
            default:
                return null;
        }

        if (name == null) return null;

        String userName = communityObj.getTokenUserName();
        if (name.equals(userName)) {
            String password = communityObj.getTokenUserPassword();
            return new TokenUser(community, userName, password);
        }
        return null;
    }
}
