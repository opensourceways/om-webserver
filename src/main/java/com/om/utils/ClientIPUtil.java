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

package com.om.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class ClientIPUtil {
    private ClientIPUtil() {
        throw new AssertionError("Utility class. Not intended for instantiation.");
    }

    /**
     * 日志记录器，用于记录 ClientIPUtil 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientIPUtil.class);

    /**
     * 获取客户端IP地址.
     *
     * @param request HTTP请求对象
     * @return 客户端IP地址字符串
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        // 获取请求主机IP地址,如果通过代理进来，则透过防火墙获取真实IP地址
        String headerName = "X-Forwarded-For";
        String ip = request.getHeader(headerName);
        if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
            // 多次反向代理后会有多个IP值，第一个IP才是真实IP,它们按照英文逗号','分割
            if (ip.indexOf(",") != -1) {
                ip = ip.split(",")[0];
            }
        }
        if (checkIp(ip)) {
            headerName = "Proxy-Client-IP";
            ip = request.getHeader(headerName);
        }
        if (checkIp(ip)) {
            headerName = "WL-Proxy-Client-IP";
            ip = request.getHeader(headerName);
        }
        if (checkIp(ip)) {
            headerName = "HTTP_CLIENT_IP";
            ip = request.getHeader(headerName);
        }
        if (checkIp(ip)) {
            headerName = "HTTP_X_FORWARDED_FOR";
            ip = request.getHeader(headerName);
        }
        if (checkIp(ip)) {
            headerName = "X-Real-IP";
            ip = request.getHeader(headerName);
        }
        if (checkIp(ip)) {
            headerName = "remote addr";
            ip = request.getRemoteAddr();
            // 127.0.0.1 ipv4, 0:0:0:0:0:0:0:1 ipv6
            if ("127.0.0.1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
                //根据网卡取本机配置的IP
                InetAddress inet = null;
                try {
                    inet = InetAddress.getLocalHost();
                } catch (UnknownHostException e) {
                    LOGGER.error("get local host error: " + e.getMessage());
                }
                if (inet != null) {
                    ip = inet.getHostAddress();
                }
            }
        }
        return ip;
    }

    private static boolean checkIp(String ip) {
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            return true;
        }
        return false;
    }
}
