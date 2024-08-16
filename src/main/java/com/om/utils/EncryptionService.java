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

import org.apache.commons.codec.binary.Base64;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 类描述：加密服务类.
 */
@Component
public final class EncryptionService {

    private EncryptionService() { }

    /**
     * RSA算法.
     */
    @Value("${rsa.authing.algorithm}")
    private String rsaAlgorithm;

    /**
     * authing token RSA key.
     */
    @Value("${rsa.authing.privateKey}")
    private String rsaAuthingPrivateKey;

    /**
     * authing token RSA key.
     */
    @Value("${rsa.authing.publicKey}")
    private String rsaAuthingPublicKey;

    /**
     * 密钥算法.
     */
    @Value("${rsa.key.algorithm}")
    private String keyAlgorithm;

    /**
     * 静态日志记录器，用于记录 EncryptionService 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionService.class);

    /**
     * sha256加密.
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    public static String getSha256Str(String str) {
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes(StandardCharsets.UTF_8));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("sha256 encrypt error {}", e.getMessage());
        }
        return encodeStr;
    }

    /**
     * sha256加密 将byte转为16进制.
     *
     * @param bytes 字节码
     * @return 加密后的字符串
     */
    private static String byte2Hex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        String temp;
        for (byte aByte : bytes) {
            temp = Integer.toHexString(aByte & 0xFF);
            if (temp.length() == 1) {
                //1得到一位的进行补0操作
                stringBuilder.append("0");
            }
            stringBuilder.append(temp);
        }
        return stringBuilder.toString();
    }

     /**
     * 公钥加密.
     *
     * @param data      明文
     * @return 加密后的数据
     * @throws NoSuchPaddingException   当填充方式不存在时抛出异常
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeyException      当密钥无效时抛出异常
     */
    public String publicEncrypt(String data) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {

        RSAPublicKey publicKey = null;
        try {
            publicKey = getPublicKey(rsaAuthingPublicKey);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("get encryption key fail {}", e.getMessage());
        }
        if (publicKey == null) {
            return  "";
        }
        Cipher cipher = Cipher.getInstance(rsaAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE,
                data.getBytes(StandardCharsets.UTF_8), publicKey.getModulus().bitLength()));
    }

    /**
     * 私钥解密.
     *
     * @param data       密文
     * @return 解密后的数据
     * @throws NoSuchPaddingException   当填充方式不存在时抛出异常
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeyException      当密钥无效时抛出异常
     */
    public String privateDecrypt(String data) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {
        RSAPrivateKey privateKey = null;
        try {
            privateKey = getPrivateKey(rsaAuthingPrivateKey);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("get encryption key fail {}", e.getMessage());
        }
        if (privateKey == null) {
            return  "";
        }
        Cipher cipher = Cipher.getInstance(rsaAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE,
                Base64.decodeBase64(data), privateKey.getModulus().bitLength()), StandardCharsets.UTF_8);
    }

    /**
     * 获取公钥.
     *
     * @param publicKey 公钥字符串
     * @return RSAPublicKey 对象
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeySpecException  当密钥规范无效时抛出异常
     */
    private RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 通过X509编码的Key指令获得公钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
        return (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
    }

    /**
     * 获取私钥.
     *
     * @param privateKey 私钥字符串
     * @return RSAPrivateKey 对象
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeySpecException  当密钥规范无效时抛出异常
     */
    private  RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
        return (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
    }

    /**
     * 对数据分段加密码、解密.
     *
     * @param cipher  密码服务
     * @param opmode  加密 or 解密
     * @param datas   需要加密或者解密的内容
     * @param keySize 密钥长度
     * @return 编解码后的数据数组
     */
    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
        int maxBlock = 0;
        if (opmode == Cipher.DECRYPT_MODE) {
            // 最大解密密文长度(密钥长度/8)
            maxBlock = keySize / 8;
        } else {
            // 最大加密明文长度(密钥长度/8-11)
            maxBlock = keySize / 8 - 66;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] dataResult = null;
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try {
            while (datas.length > offSet) {
                if (datas.length - offSet > maxBlock) {
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
            dataResult = out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Cipher Mode: " + opmode + " Error", e);
        } finally {
            IOUtils.closeQuietly(out);
        }
        return dataResult;
    }
}
