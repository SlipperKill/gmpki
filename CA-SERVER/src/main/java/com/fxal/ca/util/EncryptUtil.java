package com.fxal.ca.util;

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class EncryptUtil {
//	private static final String KEY = "abcdefgabcdefg12";
    private static final String ALGORITHMSTR = "AES/ECB/PKCS5Padding";  
    public static String base64Encode(byte[] bytes){  
        return Base64.encodeToString(bytes);
    }  
    public static byte[] base64Decode(String base64Code) throws Exception{  
        return new BASE64Decoder().decodeBuffer(base64Code);  
    }  
    public static byte[] aesEncryptToBytes(String content, String encryptKey) throws Exception {  
        KeyGenerator kgen = KeyGenerator.getInstance("AES");  
        kgen.init(128);  
        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);  
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), "AES"));  
        return cipher.doFinal(content.getBytes("utf-8"));  
    }  
    public static String aesEncrypt(String content, String encryptKey) throws Exception {  
        return base64Encode(aesEncryptToBytes(content, encryptKey));  
    }  
    public static String aesDecryptByBytes(byte[] encryptBytes, String decryptKey){  
    	try {
    	     KeyGenerator kgen = KeyGenerator.getInstance("AES");  
    	        kgen.init(128);  
    	        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);  
    	        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), "AES"));  
    	        byte[] decryptBytes = cipher.doFinal(encryptBytes);  
    	        return new String(decryptBytes);  
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
   
    }  
    public static String aesDecrypt(String encryptStr, String decryptKey){  
        try {
			return aesDecryptByBytes(base64Decode(encryptStr), decryptKey);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}  
    }  
    /**
     * 测试
     * 
     */
//    public static void main(String[] args) throws Exception {
//        String content = "123456";  //0gqIDaFNAAmwvv3tKsFOFf9P9m/6MWlmtB8SspgxqpWKYnELb/lXkyXm7P4sMf3e
//        System.out.println("加密前：" + content);  
//        System.out.println("加密密钥和解密密钥：" + KEY);  
//        String encrypt = aesEncrypt(content, KEY);  
//        System.out.println(encrypt.length()+":加密后：" + encrypt);  
//        String decrypt = aesDecrypt(encrypt, KEY);  
//        System.out.println("解密后：" + decrypt);  
//    }

}