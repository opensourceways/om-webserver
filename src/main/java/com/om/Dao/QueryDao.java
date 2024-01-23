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

package com.om.Dao;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import com.om.Modules.MessageCodeConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

/**
 * @author zhxia
 * @date 2020/10/22 12:00
 */

@Repository
public class QueryDao {
    @Value("${owner.type.api}")
    String apiFormat;

    private static final Logger logger =  LoggerFactory.getLogger(QueryDao.class);

    public String queryUserOwnertype(String community, String user) {
        String urlFormat = String.format(apiFormat, user);
        try {
            HttpResponse<JsonNode> response = Unirest.get(urlFormat)
                    .header("Content-Type", "application/json").asJson();
            String res = response.getBody().toString();
            return res;
        } catch (UnirestException e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return "{\"msg\":\"error\",\"code\":404,\"data\":null}";
        }
    }
}
