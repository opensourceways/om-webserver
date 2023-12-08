/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.Dao;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Repository;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Modules.MessageCodeConfig;



@Repository
public class GitDao {

    private static final Logger logger =  LoggerFactory.getLogger(GitDao.class);
    
    @Value("${gitee.api.token}")
    String giteeToken;

    @Value("${gitee.api.host}")
    String giteeHost;

    @Value("${github.api.token}")
    String githubToken;

    @Value("${github.api.host}")
    String githubHost;

    @Cacheable("giteeLogin")
    public String getGiteeUserIdByLogin(String giteeLogin) {
        JSONArray users = null;
        try {
            HttpResponse<JsonNode> response = Unirest.get(giteeHost + "/search/users")
                    .queryString("q", giteeLogin)
                    .queryString("per_page", 3)
                    .queryString("access_token", giteeToken)
                    .asJson();
            if (response.getStatus() == 200) {
                users = response.getBody().getArray();
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }

        if (users == null || users.length() == 0) {
            return null;
        }

        JSONObject targetUser = null;
        for (Object user : users) {
            if (user instanceof JSONObject &&
                giteeLogin.equals(((JSONObject) user).getString("login"))) {
                targetUser = (JSONObject) user;
            }
        }

        if (targetUser == null) return null;
        return Integer.toString(targetUser.getInt("id"));
    }

    @Cacheable("githubLogin")
    public String getGithubUserIdByLogin(String githubLogin) {
        JSONArray users = null;
        try {
            HttpResponse<JsonNode> response = Unirest.get(githubHost + "/search/users")
                    .header("Authorization", githubToken)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .queryString("q", githubLogin)
                    .queryString("per_page", 3)
                    .asJson();
            if (response.getStatus() == 200) {
                users = response.getBody().getObject().getJSONArray("items");
            }
        } catch (Exception e) {
            logger.error(MessageCodeConfig.E00048.getMsgEn(), e);
            return null;
        }

        if (users == null || users.length() == 0) {
            return null;
        }

        JSONObject targetUser = null;
        for (Object user : users) {
            if (user instanceof JSONObject &&
                githubLogin.equals(((JSONObject) user).getString("login"))) {
                targetUser = (JSONObject) user;
            }
        }

        if (targetUser == null) return null;
        return Integer.toString(targetUser.getInt("id"));
    }
}
