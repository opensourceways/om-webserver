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

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Repository;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import com.om.Modules.MessageCodeConfig;

/**
 * 用于与Git存储库交互的数据访问对象.
 */
@Repository
public class GitDao {
    /**
     * 日志记录器，用于记录 GitDao 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GitDao.class);

    /**
     * 存储 Gitee API token，用于访问 Gitee 的 API 接口.
     */
    @Value("${gitee.api.token}")
    private String giteeToken;

    /**
     * Gitee API 的主机地址.
     */
    @Value("${gitee.api.host}")
    private String giteeHost;

    /**
     * 存储 GitHub API token，用于访问 GitHub 的 API 接口.
     */
    @Value("${github.api.token}")
    private String githubToken;

    /**
     * GitHub API 的主机地址.
     */
    @Value("${github.api.host}")
    private String githubHost;

    /**
     * 根据 Gitee 登录名获取 Gitee 用户ID，方法结果会被缓存.
     *
     * @param giteeLogin Gitee 登录名
     * @return 对应的 Gitee 用户ID
     */
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
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }

        if (users == null || users.length() == 0) {
            return null;
        }

        JSONObject targetUser = null;
        for (Object user : users) {
            if (user instanceof JSONObject
                    && giteeLogin.equals(((JSONObject) user).getString("login"))) {
                targetUser = (JSONObject) user;
            }
        }

        if (targetUser == null) {
            return null;
        }
        return Integer.toString(targetUser.getInt("id"));
    }

    /**
     * 根据 Github 登录名获取 Github 用户ID，方法结果会被缓存.
     *
     * @param githubLogin Github 登录名
     * @return 对应的 Github 用户ID
     */
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
            LOGGER.error(MessageCodeConfig.E00048.getMsgEn() + "{}", e.getMessage());
            return null;
        }

        if (users == null || users.length() == 0) {
            return null;
        }

        JSONObject targetUser = null;
        for (Object user : users) {
            if (user instanceof JSONObject
                    && githubLogin.equals(((JSONObject) user).getString("login"))) {
                targetUser = (JSONObject) user;
            }
        }

        if (targetUser == null) {
            return null;
        }
        return Integer.toString(targetUser.getInt("id"));
    }
}
