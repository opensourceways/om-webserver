package com.om.Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;

import javax.imageio.ImageIO;

import com.alibaba.fastjson2.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.multipart.MultipartFile;

public class CommonUtil {

    private static final Logger logger =  LoggerFactory.getLogger(CommonUtil.class);
    
    public static boolean isFileContentTypeValid(MultipartFile file) throws IOException {
        try {
            byte[] fileContent = file.getBytes();

            // 验证文件头信息
            if (fileContent.length >= 2 && fileContent[0] == (byte) 0xFF && fileContent[1] == (byte) 0xD8) {
                return file.getOriginalFilename().toString().toLowerCase().endsWith(".jpg");
            } else if (fileContent.length >= 8 && fileContent[0] == (byte) 0x89 &&
                    fileContent[1] == 'P' && fileContent[2] == 'N' && fileContent[3] == 'G' &&
                    fileContent[4] == 0x0D && fileContent[5] == 0x0A && fileContent[6] == 0x1A && fileContent[7] == 0x0A) {
                return file.getOriginalFilename().toString().toLowerCase().endsWith(".png");
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return false;
    }
    
    public static InputStream rewriteImage(MultipartFile file) throws IOException{
        try {
            byte[] fileContent = check(file.getBytes());
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(fileContent);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ImageIO.write(ImageIO.read(byteArrayInputStream), "png", outputStream);
            return new ByteArrayInputStream(outputStream.toByteArray());
        } catch (Exception e) {
            throw new IOException("Rewrite image fail");
        }
    }

    public static boolean deleteFile(String path) {
        File file = new File(path);
        if (file.exists()) {
            return file.delete();
        }
        return true;
    }

    /**
     * 根据社区获取包含特定隐私版本号的隐私设置.
     *
     * @param community 社区
     * @param privacyVersions 隐私版本号
     * @return 返回包含特定隐私版本号的隐私设置
     */
    public static String getPrivacyVersionWithCommunity(String community, String privacyVersions) {
        if (privacyVersions == null || !privacyVersions.contains(":")) {
            return "";
        }

        try {
            HashMap<String, String> privacys = JSON.parseObject(privacyVersions, HashMap.class);
            String privacyAccept = privacys.get(community);
            if (privacyAccept == null) {
                return "";
            } else {
                return privacyAccept;
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            return "";
        }
    }

    /**
     * 创建隐私版本号.
     *
     * @param version 版本号
     * @param needSlash 是否需要斜杠
     * @return 返回创建的隐私版本号
     */
    public static String createPrivacyVersions(String community, String version, Boolean needSlash) {
        HashMap<String, String> privacys = new HashMap<>();
        privacys.put(community, version);
        if (needSlash) {
            return JSON.toJSONString(privacys).replaceAll("\"", "\\\\\"");
        } else {
            return JSON.toJSONString(privacys);
        }
    }

    private static byte[] check(byte[] bs) {
        if (bs != null) {
            return bs;
        }
        return null;
    }

}