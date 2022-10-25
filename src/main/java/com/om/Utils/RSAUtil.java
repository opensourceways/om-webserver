package com.om.Utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.tomcat.util.http.fileupload.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtil implements Serializable {
    public static final String RSA_ALGORITHM = "RSA";

    /**
     * 随机生成密钥对(公钥和私钥)
     *
     * @param keySize 密钥长度
     */
    public static Map<String, String> createKeys(int keySize) throws NoSuchAlgorithmException {
        //为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
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
     * 获取公钥
     *
     * @param publicKey 密钥字符串（经过base64编码）
     */
    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 通过X509编码的Key指令获得公钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
        return (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
    }

    /**
     * 获取私钥
     *
     * @param privateKey 密钥字符串（经过base64编码）
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
        return (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
    }

    /**
     * 公钥加密
     *
     * @param data      明文
     * @param publicKey 公钥
     */
    public static String publicEncrypt(String data, RSAPublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(StandardCharsets.UTF_8), publicKey.getModulus().bitLength()));
    }

    /**
     * 私钥解密
     *
     * @param data       密文
     * @param privateKey 私钥
     */
    public static String privateDecrypt(String data, RSAPrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data), privateKey.getModulus().bitLength()), StandardCharsets.UTF_8);
    }

    /**
     * 私钥加密
     *
     * @param data       明文
     * @param privateKey 私钥
     */
    public static String privateEncrypt(String data, RSAPrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(StandardCharsets.UTF_8), privateKey.getModulus().bitLength()));
    }

    /**
     * 公钥解密
     *
     * @param data      密文
     * @param publicKey 公钥
     */
    public static String publicDecrypt(String data, RSAPublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data), publicKey.getModulus().bitLength()), StandardCharsets.UTF_8);
    }

    /**
     * 对数据分段加密码、解密
     *
     * @param cipher  密码服务
     * @param opmode  加密 or 解密
     * @param datas   需要加密或者解密的内容
     * @param keySize 密钥长度
     */
    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
        int maxBlock = 0;
        if (opmode == Cipher.DECRYPT_MODE) {
            // 最大解密密文长度(密钥长度/8)
            maxBlock = keySize / 8;
        } else {
            // 最大加密明文长度(密钥长度/8-11)
            maxBlock = keySize / 8 - 11;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
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
        } catch (Exception e) {
            throw new RuntimeException("Cipher Mode: " + opmode + " Error", e);
        }
        byte[] dataResult = out.toByteArray();
        IOUtils.closeQuietly(out);
        return dataResult;
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> keyMap = RSAUtil.createKeys(3072);
        String publicKey = keyMap.get("publicKey");
        String privateKey = keyMap.get("privateKey");
        System.out.println("公钥: \n\r" + publicKey);
        System.out.println("私钥： \n\r" + privateKey);

        String token = "NvqLFTP6iDHH-RqSz8L0UVy-GYpU9UkKlWGO1_Llfb_ASqSXIa15liJXRz_PjgDpSUlP5v31hBRXxF8T1Kvl343OjStr1tAtnNXEH40HYS82KAXaIQkDCmda_lEZOcRMjpRn7sjrRPt7DhhARTGxevF12l80SjFZ4rAyRd-eL4VU6LGPupj0mJKPWSxy9JWSstzHeh9GPRnjNccj2RgoCY72ZylRFgWa8oQhnU_8tF92ZDTZMJo-gBs5z6GCGlPMhK3dtntyN1GxP_eI4LoartGUdU9E23-qEvo-VzWQV5heJYPUS9zpa1mSFjpnTrOTes6EabZfwgmTVqJXvMOyvosNYl0hVDJCsGdOgvaeCm0bnGG_gaoDnok4FtAk9QAy4yaJwSJdQljShKFsi0Pj2Pahgi7UBcaQUwiPJmVuUeSSoIMQnZ7l-KRkHVfPNzkwP-ZT1kvQ5sfVFcsE_pHwHqXmbgK6hXifbln2a-ie7mJBChrHCbMTTtMgL00fa-0afO5d_ehb9oaK7GlvH7iBfJ3TgBF8OfFivscnyc3gIO9G95641z5W2TVXH254ecmK0dUD_BgwcFUkh87-uMne9RhkZEE7wgupIHL8XqUusxcEUXGrS7YedbV9fezoe6cLVZOs0oYy82DmTZCXCn33tGl2vka0hhc_DUC9FYwxvWai_pMmFNUdyWhUUo9KRBQL8dgPtZ-EVTkDKOzST0nf6eXpiRW8P1nt_t3CRijN4K7VOriHu6Tiy5iIo_OQn_raBDSerHr2VKll_NMY_sCwEGPYerMMHxBq6MjwVx7s5ERc0fU_W3MBXsnKQCgqqeEUu0pCp0_peSx2qe9uDACAnQjslddN6Iq1FQ53NacdpzxsrCr-pYRuEc8_Ki-iizIkHDNkcOHp8Tj7gfmmB12uQDBtI7XRg5NvUEAXULpy6Sob9eNdA1-NrTnFa-9qI1ewTjioXZSoZqAvRujr1WtpPhmVW7lRZnurXeWTNjqQgSE1NP1YHK_RuuhL3qKVYId8";
        RSAPrivateKey privateKey1 = RSAUtil.getPrivateKey("MIIG_gIBADANBgkqhkiG9w0BAQEFAASCBugwggbkAgEAAoIBgQDj_g-_HhuhSao0Si-MY4T8BBPWEC6JZyKhaYIRIgPqy-1YfAiVhRLnY2no2OkV1kgQB22FaPJEtKrM0FkuHmwJxfiRr32Wv9H582Q11ipQFLyeL29wemQATHDRI4Gm9Uye5BV0qgTFvPxZsSVCvFXEwrCGPIRV9ZaeARbld5h0YRfG4npGTonXCgpurA1QUgTvfgEnM0MPz1_4M1fcN2V17UdtARmG6hAKvthOTxCRN4ZWER_PfxrRB_22gdkZhUJ2Twx2fCYu1tcfGhuYE1sAvNKIK1Rv9igKrOOXQK8c2vjxvaawZ3NhhpLv7XRpCFOOhyIapK_LgAKzVHYPdCjld06LAwoV66g1ks5BDTm2Vr9AGxJy46OyW8pGqgoPm3Sr3-AQ6b8roY5MoNvv3YiF6YnL07kwx-nZ1SLx28MeFbWyKtpQ5D5USD-6kDe4DzZURqJddkUE4S7NYFRXUYX5sDZZc2qlE2J15ggxJeG_E4kwcvxcYJQMQ0ZPMvn9fgECAwEAAQKCAYEA4sV3oB8wWFLPKseHV9o9EfZ0TH037I9bELXDG4t73fUMlPB6EU6VqPVnCKWH4aKLdvYMZ6AlKVWSdbnemlLEH0x8m1u0TVdqYXVH_YyR9alKmwSPkY8LHIjrxfnNIeXnWjt_Y9UgfhYl4oiiiSiPHvCPaFWVQ3LNZ0eqIH--cjOI1Ne7y2afD_b6vW4AqB2MrzHjr7v7PiSETnmzMGUhVBS48KEhZOI3JpkAyZM25VoXElBiFZ9VawjJwNiSuiGiQxiXhtXiAFDk1eWQOxlMtBYu0nRRYHoRXTf-zsgbotiEWvJhENN2D55WUfjiptok_boQrcrKTulQxb_RLnuyXy2TpN6ke3diaaZOz84e2Ge1l7ZeaIlA47iAul52g4y1LB8WSSPU56CU6mDKw-1qOy3k-PsGPb2I4iLeLdnxKKfKuNV_P9UQDG3H-4977MIQOUm2L7pRqoQTrnDQW8ksJG7JqtQ25rPkyxz1730k2mTq3fxnLbkS9rEtLVAV1SSJAoHBAPbbdseBoHuIux9Tmdew7VMxW-uOsNrMOPVnAv4QdW7hWF8l87l0CURTItpGzFU3B4hwzR9JEsv3FQW-xvhbipXovJOQxueJ1m7wnQSN-3_BdjRV31GpovnuFvmwK2JKk1-ks8sgWA43p4hKBLu0uvd6TswlQT4Ux6Z3vlVUImk05TD2hWje7Xf72881_nWX-GBYnuVgv6m4SLZvECo3RsRiCumyf7JaGy_IIB5A121odS0mEshEqJDMti_i4HVCTwKBwQDsb7vLqFJ7FFfe1xRIDmL5hnTbk5Ve8FqE3xgMOJSvcXs8FK_VdxtGVUZoXIgcYDOOxCQ00LL54ZMwzn_WMQDLU9bZLJaSSIlUjYB8vCLQmUyJHp1Ballkr9E_C6IUdKuB3DwRJ1N7HIRs7aA2QX0l6DI60VJgkZGwHjPnN55PAJSOnnPpFHOsZxP-vUMtyPq4qQuz5swVBUMrryD0WR89_x9DfoZyZwtZLjdSy1LRP7v-DnkMIcLIDSIcauD_tq8CgcAsgsv7E0OFotTixCdEPhG843SIl9UJzrMihK2EdCFImfdeSLCWqvaUzEzHgOaNIvwHvRcvYfSytF2lCI5F7_OgLjP6g6tpym_Q1y_ox1Um5xJSQ32d8vGBEU4xPXPFKF9EaqVEphNalOxvZbFOyzq_Lt2Qb9NAx2xsdsDqD96Yi8Ibvwe1LiUxckdjKIA2Ye2WKcSU5YoJp0HtKz-F7Sukc202UEo4NYkbZ4FrExQFFUWzm17dn4upeFANeGIyon8CgcEAsemmE6rWXf1B3dJUVaBVw9P0bSIR3T3Zr3A8pT2STK6FAAHFCkk1Aei7MV6noUqWoVBgukls0_F1E93ffiqjoVy2J_eQWgUxKanMzI-5VuR0Hh4mUQoYuFZAi0NStDfSssYpgPLps5MS5vCshQckh_jAi1flt_rx-OfRQKSugF48a1E6gWI9ZLav6hk6yuIYIAo8XyRF3291SxLeJmBFzR4DxYMY4k89z96iDLAo4oImEReM6J8i9exEBcQ7CNDLAoHAKZeEgMnoKqWO7vUefj77e66ZNVwo2YMVr0C_7uPVKtceLqMWLNjdimN00YG39LsWFNAP_yYh18RagPBQZWzRH0gufXHQIgIPPybkmzEnmZcyjydf5FOASeeFX2eeAaGlP9K3GpLcw-YUFc9P1-si2vWZ5CtY_lI_y9OnhW5Fw5pXx91tSnaMfT9OE2P2uYjAwhtww2NDIqJyJb6gyBXXT5EAdTNAaIxA47rZW-GvxlM9MC4ukHFCX1BRDGFUA0vU");
        String s = privateDecrypt(token, privateKey1);
        System.out.println(s);

        System.out.println(token.length());
    }
}