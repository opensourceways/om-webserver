/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2025
*/

package com.om.modules.privacy;

import com.om.dao.GitDao;
import com.om.dao.RedisDao;
import com.om.result.Constant;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PrivacyContentSync {
    /**
     * 日志记录器.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PrivacyContentSync.class);

    /**
     * 互斥锁.
     */
    private static final String REDIS_PRIVACY_TASK_LOCK = "privacy_content_task_lock";

    /**
     * 锁时长（分钟）.
     */
    private static final long REDIS_PRIVACY_TASK_LOCK_TIME = 2L;

    /**
     * 版本解析.
     */
    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "\\*\\*(v\\d+)\\*\\*",
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    /**
     * 定时任务线程池.
     */
    @Autowired
    @Qualifier("SR-Task-SchedulePool")
    private ThreadPoolTaskScheduler taskPool;

    /**
     * gitDao.
     */
    @Autowired
    private GitDao gitDao;

    /**
     * 使用 @Autowired 注解注入 RedisDao.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 隐私文档下载链接.
     */
    @Value("${oneid.privacy.downloadUrlZh: }")
    private String privacyDownloadUrlZh;

    /**
     * 隐私文档下载链接.
     */
    @Value("${oneid.privacy.downloadUrlEn: }")
    private String privacyDownloadUrlEn;

    /**
     * OneID 隐私政策版本号.
     */
    @Value("${oneid.privacy.version}")
    private String oneidPrivacyVersion;

    @PostConstruct
    private void init() {
        if (!StringUtils.isAnyBlank(privacyDownloadUrlZh, privacyDownloadUrlEn)) {
            taskPool.schedule(this::syncPrivacyContent, new CronTrigger("0 0 0/1 * * ?"));
        }
    }

    /**
     * 获取隐私版本信息.
     *
     * @return 版本信息
     */
    public String getPrivacyVersion() {
        if (StringUtils.isAnyBlank(privacyDownloadUrlZh, privacyDownloadUrlEn)) {
            return oneidPrivacyVersion;
        }
        String redisVersion = (String) redisDao.get(Constant.REDIS_PRIVACY_VERSION);
        if (StringUtils.isBlank(redisVersion)) {
            syncPrivacyContent();
        }
        syncPrivacyContent();
        redisVersion = (String) redisDao.get(Constant.REDIS_PRIVACY_VERSION);
        return redisVersion == null ? oneidPrivacyVersion : redisVersion;
    }

    /**
     * 获取隐私文本.
     *
     * @param language 语言
     * @return 隐私文本
     */
    public String getPrivacyContent(String language) {
        if (Constant.LANGUAGE_ZH.equals(language)) {
            return (String) redisDao.get(Constant.REDIS_PRIVACY_CONTENT_ZH);
        } else if (Constant.LANGUAGE_EN.equals(language)) {
            return (String) redisDao.get(Constant.REDIS_PRIVACY_CONTENT_EN);
        } else {
            return "";
        }
    }

    private synchronized void syncPrivacyContent() {
        if (!redisDao.acquireLock(REDIS_PRIVACY_TASK_LOCK, REDIS_PRIVACY_TASK_LOCK, REDIS_PRIVACY_TASK_LOCK_TIME)) {
            LOGGER.warn("privacy content sync has been running on other pod");
            return;
        }
        LOGGER.info("privacy content sync start");
        try {
            String contentZh = gitDao.getPrivacyContent(privacyDownloadUrlZh);
            String contentEn = gitDao.getPrivacyContent(privacyDownloadUrlEn);
            if (StringUtils.isBlank(contentZh)) {
                LOGGER.error("privacy zh file content is null");
                return;
            }
            if (StringUtils.isBlank(contentEn)) {
                LOGGER.error("privacy en file content is null");
                return;
            }
            String versionZh = parseVersion(contentZh);
            String versionEn = parseVersion(contentEn);
            if (StringUtils.isBlank(versionZh)) {
                LOGGER.error("parse privacy version failed");
                return;
            }
            if (!StringUtils.equals(versionZh, versionEn)) {
                LOGGER.error("zh/en privacy version is different");
                return;
            }
            String privacyVersionOld = (String) redisDao.get(Constant.REDIS_PRIVACY_VERSION);
            if (StringUtils.equals(versionZh, privacyVersionOld)) {
                LOGGER.warn("privacy version is not changed");
                return;
            }
            redisDao.set(Constant.REDIS_PRIVACY_VERSION, versionZh, 0L);
            redisDao.set(Constant.REDIS_PRIVACY_CONTENT_ZH, contentZh, 0L);
            redisDao.set(Constant.REDIS_PRIVACY_CONTENT_EN, contentEn, 0L);
        } catch (Exception e) {
            LOGGER.error("sync privacy content failed {}", e.getMessage());
        }
        LOGGER.info("privacy content sync end");
    }

    private String parseVersion(String content) {
        String[] contentLines = content.split("\n");
        for (int i = contentLines.length - 1; i >= 0; i--) {
            String trimmedLine = contentLines[i].trim();
            Matcher matcher = VERSION_PATTERN.matcher(trimmedLine);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }
}
