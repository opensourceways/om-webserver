package com.om.Utils;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

@Repository
public class IpUtil {
    @Autowired
    private Environment env;

    private static final String UNKNOWN = "unknown";

    private static final String SEPARATOR = ",";

    private static List<String> headerIpKeys;

    @PostConstruct
    public void init() {
        headerIpKeys =
                Arrays.asList(env.getProperty("request.header.ip.keys", "x-forwarded-for").split(","));
    }

    public static String getIpFromRequest(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        // 从多个header key获取IP，获取到就break
        String ip = UNKNOWN;
        for (String headerIpKey : headerIpKeys) {
            if (StringUtils.isBlank(ip) || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(headerIpKey);
            } else {
                break;
            }
        }

        // 多个header key都未获取IP，获取Remote Address
        if (StringUtils.isBlank(ip) || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // 对于通过多个代理的情况，取出第一个 IP
        if (ip != null && ip.contains(SEPARATOR)) {
            ip = ip.substring(0, ip.indexOf(SEPARATOR));
        }

        return ip;
    }

}
