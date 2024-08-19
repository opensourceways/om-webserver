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

package com.om.dao;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import com.om.modules.MessageCodeConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

/**
 * 数据查询对象类.
 */
@Repository
public class QueryDao {
    /**
     * 持有者类型 API 格式.
     */
    @Value("${owner.type.api}")
    private String apiFormat;

    /**
     * 日志记录器，用于记录 QueryDao 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(QueryDao.class);

    /**
     * 查询用户持有者类型.
     *
     * @param community 社区
     * @param user      用户
     * @return 用户持有者类型信息
     */
    public String queryUserOwnertype(String community, String user) {
        String urlFormat = String.format(apiFormat, user);
        try {
            HttpResponse<JsonNode> response = Unirest.get(urlFormat)
                    .header("Content-Type", "application/json").asJson();
            String res = response.getBody().toString();
            return res;
        } catch (UnirestException e) {
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return "{\"msg\":\"error\",\"code\":404,\"data\":null}";
        }
    }
}
