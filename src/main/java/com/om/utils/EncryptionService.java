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

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 类描述：加密服务类.
 */
@Component
public class EncryptionService {
    /**
     * GCM模式下的IV长度.
     */
    private static final int GCM_IV_LENGTH = 12;

    /**
     * GCM模式下的TAG长度.
     */
    private static final int GCM_TAG_LENGTH = 16;

    /**
     * 密钥生成器.
     */
    private SecretKeySpec secretKeySpec;

    /**
     * 安全随机数.
     */
    private SecureRandom secureRandom;

    /**
     * 静态日志记录器，用于记录 EncryptionService 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionService.class);

    /**
     * 加密算法.
     */
    @Value("${aes.key.idToken}")
    private String aesKey;

    /**
     * 加密算法.
     */
    @Value("${aes.authing.idToken}")
    private String aesAuthing;

    /**
     * 秘钥.
     */
    @Value("${aes.secret.idToken}")
    private String aesSecret;

    /**
     * 初始化方法.
     */
    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(aesSecret);
        if (keyBytes.length != 32) { // 确保密钥长度为256位
            LOGGER.error("无效的密钥长度（必须是32字节）");
            throw new IllegalArgumentException("无效的密钥长度（必须是32字节）");
        }
        secretKeySpec = new SecretKeySpec(keyBytes, aesKey);
        try {
            secureRandom = SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(256, DrbgParameters.Capability.RESEED_ONLY, null));
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("init secureRandom failed {}", e.getMessage());
        }
    }

    /**
     * 加密.
     *
     * @param plaintext 原文
     * @return 加密值
     * @throws Exception 异常
     */
    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(aesAuthing);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedData = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * 解密.
     *
     * @param ciphertext 密文
     * @return 解密后数据
     * @throws Exception 异常
     */
    public String decrypt(String ciphertext) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(ciphertext);

        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(decodedData, 0, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance(aesAuthing);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);

        byte[] decryptedData = cipher.doFinal(decodedData, GCM_IV_LENGTH, decodedData.length - GCM_IV_LENGTH);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}
