/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.utils;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RSAUtil implements Serializable {
    /**
     * 密钥算法.
     */
    private static String keyAlgorithm;

    /**
     * RSA算法.
     */
    private static String rsaAlgorithm;

    /**
     * 设置密钥算法.
     *
     * @param keyAlgorithm 密钥算法
     */
    @Value("${rsa.key.algorithm}")
    public void setKeyAlgorithm(String keyAlgorithm) {
        setKeyAlgorithmStaticMethod(keyAlgorithm);
    }

    /**
     * 通过静态方法设置密钥算法.
     *
     * @param keyAlgorithm 密钥算法
     */
    public static void setKeyAlgorithmStaticMethod(String keyAlgorithm) {
        RSAUtil.keyAlgorithm = keyAlgorithm;
    }

    /**
     * 设置 RSA 算法.
     *
     * @param rsaAlgorithm RSA 算法
     */
    @Value("${rsa.authing.algorithm}")
    public void setRsaAlgorithm(String rsaAlgorithm) {
        setRsaAlgorithmStaticMethod(rsaAlgorithm);
    }

    /**
     * 通过静态方法设置RSA算法.
     *
     * @param rsaAlgorithm 密钥算法
     */
    public static void setRsaAlgorithmStaticMethod(String rsaAlgorithm) {
        RSAUtil.rsaAlgorithm = rsaAlgorithm;
    }

    /**
     * 随机生成密钥对(公钥和私钥).
     *
     * @param keySize 密钥大小
     * @return 包含公钥和私钥的映射
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     */
    public static Map<String, String> createKeys(int keySize) throws NoSuchAlgorithmException {
        //为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(rsaAlgorithm);
        //初始化KeyPairGenerator对象,密钥长度
        kpg.initialize(keySize);
        //生成密匙对
        KeyPair keyPair = kpg.generateKeyPair();
        //得到公钥
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = Base64.encodeBase64URLSafeString(publicKey.getEncoded());
        //得到私钥
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = Base64.encodeBase64URLSafeString(privateKey.getEncoded());

        Map<String, String> keyPairMap = new HashMap<>();
        keyPairMap.put("publicKey", publicKeyStr);
        keyPairMap.put("privateKey", privateKeyStr);
        return keyPairMap;
    }

    /**
     * 获取公钥.
     *
     * @param publicKey 公钥字符串
     * @return RSAPublicKey 对象
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeySpecException  当密钥规范无效时抛出异常
     */
    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
        return (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
    }

    /**
     * 公钥加密.
     *
     * @param data      明文
     * @param publicKey 公钥
     * @return 加密后的数据
     * @throws NoSuchPaddingException   当填充方式不存在时抛出异常
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeyException      当密钥无效时抛出异常
     */
    public static String publicEncrypt(String data, RSAPublicKey publicKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(rsaAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE,
                data.getBytes(StandardCharsets.UTF_8), publicKey.getModulus().bitLength()));
    }

    /**
     * 私钥解密.
     *
     * @param data       密文
     * @param privateKey 私钥
     * @return 解密后的数据
     * @throws NoSuchPaddingException   当填充方式不存在时抛出异常
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeyException      当密钥无效时抛出异常
     */
    public static String privateDecrypt(String data, RSAPrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(rsaAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE,
                Base64.decodeBase64(data), privateKey.getModulus().bitLength()), StandardCharsets.UTF_8);
    }

    /**
     * 私钥加密.
     *
     * @param data       明文
     * @param privateKey 私钥
     * @return 加密后的数据
     * @throws NoSuchPaddingException   当填充方式不存在时抛出异常
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeyException      当密钥无效时抛出异常
     */
    public static String privateEncrypt(String data, RSAPrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(rsaAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE,
                data.getBytes(StandardCharsets.UTF_8), privateKey.getModulus().bitLength()));
    }

    /**
     * 公钥解密.
     *
     * @param data      密文
     * @param publicKey 公钥
     * @return 解密后的数据
     * @throws NoSuchPaddingException   当填充方式不存在时抛出异常
     * @throws NoSuchAlgorithmException 当算法不存在时抛出异常
     * @throws InvalidKeyException      当密钥无效时抛出异常
     */
    public static String publicDecrypt(String data, RSAPublicKey publicKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(rsaAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE,
                Base64.decodeBase64(data), publicKey.getModulus().bitLength()), StandardCharsets.UTF_8);
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
