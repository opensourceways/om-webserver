package com.om.service;

public interface ModeratorServiceInterface {
    /**
     * 检查文本敏感信息.
     *
     * @param text      文本内容
     * @param eventType 检查文本类型
     * @return 是否检测通过
     */
    boolean checkText(String text, String eventType);

    /**
     * 检测图片敏感信息.
     *
     * @param imageUrl     图片url
     * @param needDownload 图片是否需要下载
     * @param eventType    检查图片类型
     * @return 检测结果
     */
    boolean checkImage(String imageUrl, boolean needDownload, String eventType);
}
