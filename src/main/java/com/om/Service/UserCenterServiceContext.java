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

import com.om.Service.inter.UserCenterServiceInter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserCenterServiceContext {
    /**
     * 自动注入用户中心服务映射.
     */
    @Autowired
    private Map<String, UserCenterServiceInter> userCenterServiceMap;

    /**
     * 获取特定类型的用户中心服务.
     *
     * @param type 服务类型
     * @return 对应的用户中心服务接口
     */
    public UserCenterServiceInter getUserCenterService(String type) {
        return userCenterServiceMap.get(type);
    }

}
