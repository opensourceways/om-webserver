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
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import javax.imageio.ImageIO;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
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
     * sha256加密.
     *
     * @param data 数据
     * @param salt 盐
     * @return 加密后数据
     * @throws NoSuchAlgorithmException 异常
     */
    public static String encryptSha256(String data, String salt) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("encryptSha256 failed {}", e.getMessage());
            return null;
        }
        // 将盐值和数据拼接后进行哈希计算
        String combinedData = data + salt;
        byte[] hashBytes = md.digest(combinedData.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = String.format("%02X", b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * 获取调用接口路径（防uri鉴权绕过）.
     *
     * @param request 请求体
     * @return uri
     */
    public static String getSafeRequestUri(HttpServletRequest request) {
        return request.getServletPath() + (request.getPathInfo() != null ? request.getPathInfo() : "");
    }

    /**
     * 根据url下载图片base64.
     *
     * @param imageUrl url
     * @param maxSize 最大图片大小
     * @return base64数据
     */
    public static String getBase64FromURL(String imageUrl, int maxSize) {
        URL url = null;
        try {
            url = new URL(imageUrl);
        } catch (MalformedURLException e) {
            LOGGER.error("Error: imageurl is invalid");
            return "Error: imageurl is invalid";
        }
        try (InputStream inputStream = url.openStream();
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            URLConnection uConnection = url.openConnection();
            if (uConnection.getContentLength() > maxSize) {
                LOGGER.error("Error occurs when checking images. Only support images smaller than " + maxSize);
                return "Error occurs when checking images";
            }
            byte[] buffer = new byte[4096];
            int n = 0;
            while ((n = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, n);
            }
            byte[] imageBytes = outputStream.toByteArray();
            String base64Encoded = Base64.getEncoder().encodeToString(imageBytes);
            return base64Encoded;
        } catch (IOException e) {
            LOGGER.error("Error: Could not read image");
            return "Error: Could not read image";
        }
    }

    /**
     * 数组切片.
     *
     * @param originList 元数据
     * @param chunkSize 切片大小
     * @return 返回值
     */
    public static List<List<String>> splitList(List<String> originList, int chunkSize) {
        List<List<String>> splits = new ArrayList<>();
        if (CollectionUtils.isEmpty(originList)) {
            return splits;
        }
        for (int i = 0; i < originList.size(); i += chunkSize) {
            List<String> chunk = new ArrayList<>();
            for (int j = i; j < Math.min(i + chunkSize, originList.size()); j++) {
                chunk.add(originList.get(j));
            }
            splits.add(chunk);
        }
        return splits;
    }

    private static byte[] check(byte[] bs) {
        if (bs != null) {
            return bs;
        }
        return null;
    }
}
