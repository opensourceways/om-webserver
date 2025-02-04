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

package com.om.controller.init;

import com.om.utils.LogUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.web.bind.annotation.RestController;

import com.om.utils.CommonUtil;

/**
 * 实现了 ApplicationRunner 接口的 InitController 类，用于初始化控制器.
 */
@RestController
public class InitController implements ApplicationRunner {
    /**
     * redis路径.
     */
    @Value("${redis.path:}")
    private String redisPath;

    private void deleteRedis() {
        if (StringUtils.isBlank(redisPath)) {
            LogUtil.createLogs("system", "delete file", "application init",
                    "system delete file redis", "localhost", "failed,file not found");
            return;
        }
        if (CommonUtil.deleteFile(redisPath)) {
            LogUtil.createLogs("system", "delete file", "application init",
                    "system delete file redis", "localhost", "success");
        } else {
            LogUtil.createLogs("system", "delete file", "application init",
                    "system delete file redis", "localhost", "failed");
        }
    }

    private void deleteApplicationConfig() {
        String applicationPath = System.getenv("APPLICATION_PATH");
        if (StringUtils.isBlank(applicationPath)) {
            LogUtil.createLogs("system", "delete file", "application init",
                    "system delete file application.yaml", "localhost", "failed,file not found");
            return;
        }
        if (CommonUtil.deleteFile(applicationPath)) {
            LogUtil.createLogs("system", "delete file", "application init",
                    "system delete file application.yaml", "localhost", "success");
        } else {
            LogUtil.createLogs("system", "delete file", "application init",
                    "system delete file application.yaml", "localhost", "failed");
        }
    }

    /**
     * 运行应用程序的方法.
     *
     * @param args 应用程序参数
     * @throws Exception 可能抛出的异常
     */
    @Override
    public void run(ApplicationArguments args) throws Exception {
        deleteApplicationConfig();
        deleteRedis();
    }
}
