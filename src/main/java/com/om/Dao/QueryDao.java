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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.om.Utils.*;
import org.asynchttpclient.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author zhxia
 * @date 2020/10/22 12:00
 */

@Repository
public class QueryDao {
    @Autowired
    AsyncHttpUtil asyncHttpUtil;

    @Value("${esurl}")
    String url;

    static ObjectMapper objectMapper = new ObjectMapper();

    public String queryAllUserOwnertype(String community) {
        String queryStr = "{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"query_string\":{\"analyze_wildcard\":true,\"query\":\"!is_removed:1\"}}]}},\"aggs\":{\"group_field\":{\"terms\":{\"field\":\"sig_name.keyword\",\"size\":500},\"aggs\":{\"user\":{\"terms\":{\"field\":\"user_login.keyword\",\"size\":1000,\"min_doc_count\":1},\"aggs\":{\"type\":{\"terms\":{\"field\":\"owner_type.keyword\"},\"aggs\":{}}}}}}}}";
        String index;

        switch (community.toLowerCase()) {
            case "openeuler":
                index = "/openeuler_sigs_pure_committers_20220210";
                break;
            case "opengauss":
                index = "/opengauss_sigs_committers_20220518";
                break;
            default:
                return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }

        try {
            AsyncHttpClient client = AsyncHttpUtil.getClient();
            RequestBuilder builder = asyncHttpUtil.getBuilder();
            builder.setUrl(this.url + index + "/_search");
            builder.setBody(queryStr);
            ListenableFuture<Response> f = client.executeRequest(builder.build());
            String responseBody = f.get().getResponseBody(UTF_8);
            JsonNode dataNode = objectMapper.readTree(responseBody);
            Iterator<JsonNode> buckets = dataNode.get("aggregations").get("group_field").get("buckets").elements();

            HashMap<String, ArrayList<Object>> userData = new HashMap<>();
            while (buckets.hasNext()) {
                JsonNode bucket = buckets.next();
                String sig = bucket.get("key").asText();
                Iterator<JsonNode> users = bucket.get("user").get("buckets").elements();
                while (users.hasNext()) {
                    JsonNode userBucket = users.next();
                    String user = userBucket.get("key").asText();
                    Iterator<JsonNode> types = userBucket.get("type").get("buckets").elements();
                    ArrayList<String> typeList = new ArrayList<>();
                    while (types.hasNext()) {
                        JsonNode type = types.next();
                        typeList.add(type.get("key").asText());
                    }
                    HashMap<String, Object> user_type = new HashMap<>();
                    user_type.put("sig", sig);
                    user_type.put("type", typeList);

                    if (userData.containsKey(user.toLowerCase())) {
                        userData.get(user.toLowerCase()).add(user_type);
                    } else {
                        ArrayList<Object> templist = new ArrayList<>();
                        templist.add(user_type);
                        userData.put(user.toLowerCase(), templist);
                    }
                }
            }
            HashMap<String, Object> resMap = new HashMap<>();
            resMap.put("code", 200);
            resMap.put("data", userData);
            resMap.put("msg", "success");
            return objectMapper.valueToTree(resMap).toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"code\":400,\"data\":\"query error\",\"msg\":\"query error\"}";
        }
    }
}
