/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.service;

import com.om.dao.RedisDao;
import com.om.result.Constant;
import com.om.utils.CommonUtil;
import kong.unirest.Headers;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ModeratorService {
    /**
     * 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ModeratorService.class);

    /**
     * 图片审核，最大图片大小是10M.
     */
    private static final int PIC_MAX_SIZE = 10485760;

    /**
     * 使用 @Autowired 注解注入 RedisDao.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 云账号.
     */
    @Value("${sensitive.moderator.domain}")
    private String mDomain;

    /**
     * 用户名.
     */
    @Value("${sensitive.moderator.name}")
    private String mName;

    /**
     * 密码.
     */
    @Value("${sensitive.moderator.password}")
    private String mPassword;

    /**
     * 项目ID.
     */
    @Value("${sensitive.moderator.project-id}")
    private String mProjectId;

    /**
     * 项目名.
     */
    @Value("${sensitive.moderator.project-name}")
    private String mProjectName;

    /**
     * 获取token的url.
     */
    @Value("${sensitive.moderator.token-url}")
    private String moderatorTokenUrl;

    /**
     * token过期时长.
     */
    @Value("${sensitive.moderator.token-expire}")
    private Long moderatorTokenExpire;

    /**
     * 文本检查.
     */
    @Value("${sensitive.moderator.text-url}")
    private String moderatorUrl;

    /**
     * 图片检查.
     */
    @Value("${sensitive.moderator.image-url}")
    private String moderatorImageUrl;

    /**
     * 获取token信息.
     *
     * @return token
     */
    private String getToken() {
        try {
            String sBodyTemplate = String.join("",
                    "{",
                    "\"auth\": {",
                    "\"identity\": {",
                    "\"methods\": [\"password\"], ",
                    "\"password\": {",
                    "\"user\": {",
                    "\"domain\": {",
                    "\"name\": \"%s\"",
                    "}, ",
                    "\"name\": \"%s\", ",
                    "\"password\": \"%s\"",
                    "}",
                    "}",
                    "}, ",
                    "\"scope\": {",
                    "\"project\": {",
                    "\"id\": \"%s\", ",
                    "\"name\": \"%s\"",
                    "}",
                    "}",
                    "}",
                    "}"
            );
            String sBody = String.format(sBodyTemplate, mDomain, mName, mPassword,
                    mProjectId, mProjectName);
            HttpResponse<JsonNode> response = Unirest.post(moderatorTokenUrl)
                    .header("Content-Type", "application/json;charset=utf8")
                    .body(sBody)
                    .asJson();
            Headers headers = response.getHeaders();
            return headers.getFirst("X-Subject-Token");
        } catch (Exception e) {
            LOGGER.error("get moderator token failed {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 检查文本敏感信息.
     *
     * @param text 文本内容
     * @return 是否检测通过
     */
    public boolean checkText(String text, String eventType) {
        try {
            String url = String.format(moderatorUrl, mProjectId);
            String sBodyTemplate = String.join("",
                    """
                            {
                                "event_type": "%s",
                                "data": {
                                    "text": "%s",
                                    "language": "%s"
                                }
                            }
                            """
            );
            String sBody = String.format(sBodyTemplate, eventType, text, Constant.MODERATOR_V3_LANGUAGE_ZH);
            String token = (String) redisDao.get(Constant.REDIS_KEY_MODERATOR_TOKEN);
            if (StringUtils.isBlank(token)) {
                token = getToken();
                redisDao.set(Constant.REDIS_KEY_MODERATOR_TOKEN, token, moderatorTokenExpire);
            }
            HttpResponse<JsonNode> response = Unirest.post(url)
                    .header("X-Auth-Token", token)
                    .header("Content-Type", "application/json;charset=utf8")
                    .body(sBody)
                    .asJson();
            if (response.getStatus() != 200) {
                LOGGER.error("moderator service error {}", response.getBody().getObject().toString());
                redisDao.remove(Constant.REDIS_KEY_MODERATOR_TOKEN);
                return false;
            }
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("result");
            String suggestion = jsonObject.getString("suggestion");
            if ("block".equals(suggestion) || "review".equals(suggestion)) {
                LOGGER.error("text is invalid, suggestion is {}, text is {}, eventType is {}", jsonObject.getString("suggestion"), text, eventType);
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.error("moderator service error {}", e.getMessage());
            redisDao.remove(Constant.REDIS_KEY_MODERATOR_TOKEN);
            return false;
        }
    }

    /**
     * 检测图片敏感信息.
     *
     * @param imageUrl 图片url
     * @param needDownload 图片是否需要下载
     * @return 检测结果
     */
    public boolean checkImage(String imageUrl, boolean needDownload) {
        try {
            String url = String.format(moderatorImageUrl, mProjectId);
            String sBodyTemplate = String.join("",
                    "{",
                    "\"%s\": \"%s\", ",
                    "\"categories\": [\"all\"]",
                    "}"
            );
            String mode;
            String sBody;
            if (needDownload) {
                mode = "image";
                String base64Image = CommonUtil.getBase64FromURL(imageUrl, PIC_MAX_SIZE);
                if (base64Image.contains("Error")) {
                    LOGGER.error("base64 pic failed");
                    return false;
                }
                sBody = String.format(sBodyTemplate, mode, base64Image);
            } else {
                mode = "url";
                sBody = String.format(sBodyTemplate, mode, imageUrl);
            }
            String token = (String) redisDao.get(Constant.REDIS_KEY_MODERATOR_TOKEN);
            if (StringUtils.isBlank(token)) {
                token = getToken();
                redisDao.set(Constant.REDIS_KEY_MODERATOR_TOKEN, token, moderatorTokenExpire);
            }

            HttpResponse<JsonNode> response = Unirest.post(url)
                    .header("X-Auth-Token", token)
                    .header("Content-Type", "application/json;charset=utf8")
                    .body(sBody)
                    .asJson();
            if (response.getStatus() != 200) {
                LOGGER.error("moderator service error {}", response.getBody().getObject().toString());
                redisDao.remove(Constant.REDIS_KEY_MODERATOR_TOKEN);
                return false;
            }
            JSONObject jsonObject = response.getBody().getObject().getJSONObject("result");
            if (jsonObject.has("error_code")) {
                LOGGER.error("moderator service error {}", jsonObject.toString());
                return false;
            }
            if ("block".equals(jsonObject.getString("suggestion"))) {
                LOGGER.error("text is invalid");
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.error("moderator service error {}", e.getMessage());
            redisDao.remove(Constant.REDIS_KEY_MODERATOR_TOKEN);
            return false;
        }
    }
}
