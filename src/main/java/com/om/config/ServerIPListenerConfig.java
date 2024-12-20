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

package com.om.config;

import com.om.utils.LogUtil;
import org.apache.catalina.connector.Connector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Component
public class ServerIPListenerConfig implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {
    /**
     * Logger for logging messages in ServerIPListenerConfig class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ServerIPListenerConfig.class);

    /**
     * 绑定IP.
     *
     * @param factory 服务工厂
     */
    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        try {
            InetAddress localAddress = InetAddress.getLocalHost();
            factory.addConnectorCustomizers((Connector connector) -> {
                connector.setProperty("address", localAddress.getHostAddress());
            });
            LogUtil.createLogs("system", "sys set", "application init",
                    "system set ip address", localAddress.getHostAddress(), "success");
        } catch (UnknownHostException e) {
            LOGGER.error("set ip address failed {}", e.getMessage());
            LogUtil.createLogs("system", "sys set", "application init",
                    "system set ip address", "localhost", "failed");
        }
    }
}
