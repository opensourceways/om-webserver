package com.om.Service;


import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.UdfTargetType;
import cn.authing.core.types.UserDefinedData;
import cn.authing.core.types.UdfDataType;
import cn.authing.core.types.UserDefinedDataInput;
import cn.authing.core.types.UserDefinedField;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;


/**
 * 类描述：隐私签署同意记录保存操作类.
 */
@Component
public class PrivacyHistoryService {

    /**
     * 隐私历史记录字段名.
     */
    private static final String PRIVACY_HISTORY_COLUMN_PREFIX = "privacy_history";

    /**
     * 隐私历史记录字段注释.
     */
    private static final String PRIVACY_HISTORY_LABEL = "PrivacyHistory";

    /**
     * 隐私历史记录条数.
     */
    private static final Integer HISTORY_MAX_NUMBER = 50;

    /**
     * 日志记录器，用于记录身份验证拦截器的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PrivacyHistoryService.class);

    /**
     * 用户池id.
     */
    @Value("${authing.userPoolId}")
    private String userPoolId;

    /**
     * 社区名称.
     */
    @Value("${community}")
    private String community;

    /**
     * 用户池secret.
     */
    @Value("${authing.secret}")
    private String authingSecret;

    /**
     * authing客户端操作实体.
     */
    private ManagementClient managementClient;

    /**
     * 初始化authing链接，初始化隐私协议字段.
     */
    @PostConstruct
    private void init() {
        try {
            // 初始化authing连接
            managementClient = new ManagementClient(userPoolId, authingSecret);
            // 查询所有字段
            List<UserDefinedField> list = managementClient.udf().list(UdfTargetType.USER).execute();
            for (UserDefinedField userDefinedField : list) {
                if ((PRIVACY_HISTORY_COLUMN_PREFIX + '_' + community).equals(userDefinedField.getKey())) {
                    return;
                }
            }
            // 初始化本服务的隐私历史记录字段
            managementClient.udf()
                    .set(UdfTargetType.USER, PRIVACY_HISTORY_COLUMN_PREFIX + "_" + community,
                            UdfDataType.STRING, community + PRIVACY_HISTORY_LABEL)
                    .execute();
        } catch (Exception e) {
            LOGGER.error("PrivacyHistory init fail {}", e.getMessage());
        }
    }

    /**
     * 传入隐私签署记录保存到历史记录.
     * @param privacyContent 传入的需要保存的签署记录内容
     * @param userId 用户id
     */
    public void savePrivacyHistory(String privacyContent, String userId) {
        if (StringUtils.isEmpty(privacyContent) || StringUtils.isEmpty(userId)) {
            return;
        }
        try {
            // 查询用户之前的全量历史隐私签署信息
            List<UserDefinedData> list = managementClient.udf().listUdv(UdfTargetType.USER, userId).execute();
            String privacyAll = "";
            for (UserDefinedData userDefinedData : list) {
                if ((PRIVACY_HISTORY_COLUMN_PREFIX + "_" + community).equals(userDefinedData.getKey())) {
                    privacyAll = userDefinedData.getValue();
                }
            }
            // 头插法加入历史记录。
            privacyAll = privacyContent + ";" + privacyAll;
            // 去重。
            List<String> newList = Arrays.stream(privacyAll.split(";")).distinct()
                    .filter(StringUtils::isNotBlank).collect(Collectors.toList());
            // 保留最新20个签署记录。
            newList = newList.subList(0, Math.min(newList.size(), HISTORY_MAX_NUMBER));

            String newPrivacy = String.join(";", newList);
            // 封装入参保存
            managementClient.udf().setUdvBatch(UdfTargetType.USER, userId, Collections
                    .singletonList(new UserDefinedDataInput((PRIVACY_HISTORY_COLUMN_PREFIX + "_" + community),
                            newPrivacy))).execute();
        } catch (Exception e) {
            LOGGER.error("PrivacyHistory save fail {}", e.getMessage());
        }
    }

}
