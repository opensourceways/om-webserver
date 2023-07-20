package com.om.Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

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

    private static byte[] check(byte[] bs) {
        if (bs != null) {
            return bs;
        }
        return null;
    }

}