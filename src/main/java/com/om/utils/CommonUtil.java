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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import javax.imageio.ImageIO;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.multipart.MultipartFile;

public final class CommonUtil {
    private CommonUtil() {
        throw new AssertionError("Utility class. Not intended for instantiation.");
    }

    /**
     * 日志记录器，用于记录 CommonUtil 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CommonUtil.class);

    /**
     * 检查文件内容类型是否有效.
     *
     * @param file 要检查的文件
     * @return 如果文件内容类型有效，则返回 true；否则返回 false
     * @throws IOException 当发生输入输出异常时抛出
     */
    public static boolean isFileContentTypeValid(MultipartFile file) throws IOException {
        try {
            byte[] fileContent = file.getBytes();
            String originalFilename = file.getOriginalFilename();
            // 验证文件头信息
            if (fileContent.length >= 2 && fileContent[0] == (byte) 0xFF && fileContent[1] == (byte) 0xD8) {
                if (Objects.nonNull(originalFilename)) {
                    return originalFilename.toLowerCase().endsWith(".jpg");
                }
            } else if (fileContent.length >= 8 && fileContent[0] == (byte) 0x89
                    && fileContent[1] == 'P' && fileContent[2] == 'N' && fileContent[3] == 'G'
                    && fileContent[4] == 0x0D && fileContent[5] == 0x0A && fileContent[6] == 0x1A
                    && fileContent[7] == 0x0A) {
                if (Objects.nonNull(originalFilename)) {
                    return originalFilename.toLowerCase().endsWith(".png");
                }
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
        }
        return false;
    }

    /**
     * 重写图像文件并返回输入流.
     *
     * @param file 要重写的图像文件
     * @return 重写后的图像文件的输入流
     * @throws IOException 当发生输入输出异常时抛出
     */
    public static InputStream rewriteImage(MultipartFile file) throws IOException {
        byte[] fileContent = check(file.getBytes());
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(fileContent);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            ImageIO.write(ImageIO.read(byteArrayInputStream), "png", outputStream);
            return new ByteArrayInputStream(outputStream.toByteArray());
        } catch (RuntimeException e) {
            LOGGER.error("Internal Server RuntimeException" + e.getMessage());
            throw new IOException("Rewrite image fail");
        } catch (Exception e) {
            throw new IOException("Rewrite image fail");
        }
    }

    /**
     * 删除文件.
     *
     * @param path 文件路径
     * @return 如果文件删除成功则返回 true，否则返回 false
     */
    public static boolean deleteFile(String path) {
        File file = new File(path);
        if (file.exists()) {
            return file.delete();
        }
        return true;
    }

    /**
     * 字符串为空或者null，则判定为相等.
     *
     * @param src 第一个字符串
     * @param dec 第二个字符串
     * @return 字符串是否相同
     */
    public static boolean isStringEquals(String src, String dec) {
        String srcTmp = src == null ? "" : src;
        String decTmp = dec == null ? "" : dec;
        return StringUtils.equals(srcTmp, decTmp);
    }

    private static byte[] check(byte[] bs) {
        if (bs != null) {
            return bs;
        }
        return null;
    }
}