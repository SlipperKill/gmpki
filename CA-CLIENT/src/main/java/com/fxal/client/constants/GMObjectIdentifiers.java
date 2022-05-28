package com.fxal.client.constants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface GMObjectIdentifiers {

    ASN1ObjectIdentifier ecc_pub_key = new ASN1ObjectIdentifier("1.2.840.10045.2.1"); //ecc 公钥标识

    String sm = "1.2.156.10197.1"; // 国家密码算法标识

    ASN1ObjectIdentifier sm_2 = new ASN1ObjectIdentifier(sm + ".301");//SM2算法标识
    ASN1ObjectIdentifier sm_2_sign = new ASN1ObjectIdentifier(sm_2 + ".1");//SM2签名算法标识
    ASN1ObjectIdentifier sm_2_exchange = new ASN1ObjectIdentifier(sm_2 + ".2");//SM2密钥交换标识
    ASN1ObjectIdentifier sm_2_encrypt = new ASN1ObjectIdentifier(sm_2 + ".3");//SM2加密算法标识

    ASN1ObjectIdentifier sm_3 = new ASN1ObjectIdentifier(sm + ".401");//SM3杂凑算法标识
    ASN1ObjectIdentifier sm_3_no_key = new ASN1ObjectIdentifier(sm_3 + ".1");//SM3密码杂凑算法，无密钥使用
    ASN1ObjectIdentifier sm_3_has_key = new ASN1ObjectIdentifier(sm_3 + ".2");//SM3密码杂凑算法，有密钥使用

    ASN1ObjectIdentifier sm_4 = new ASN1ObjectIdentifier(sm + ".104");//SM4
    ASN1ObjectIdentifier sm_4_ecb = new ASN1ObjectIdentifier(sm_4 + ".1");//SM4-ECB
    ASN1ObjectIdentifier sm_4_cbc = new ASN1ObjectIdentifier(sm_4 + ".2");//SM4-CBC

    ASN1ObjectIdentifier sm2_with_sm3 = new ASN1ObjectIdentifier("1.2.156.10197.1.501");//基于SM2算法和SM3算法的签名

    String content_type = "1.2.156.10197.6.1.4.2"; //SM2密码算法加密签名消息语法规范
    ASN1ObjectIdentifier data = new ASN1ObjectIdentifier(content_type + ".1");
    ASN1ObjectIdentifier signed_data = new ASN1ObjectIdentifier(content_type + ".2");
    ASN1ObjectIdentifier enveloped_data = new ASN1ObjectIdentifier(content_type + ".3");
    ASN1ObjectIdentifier signed_and_enveloped_data = new ASN1ObjectIdentifier(content_type + ".4");
    ASN1ObjectIdentifier encrypted_data = new ASN1ObjectIdentifier(content_type + ".5");
    ASN1ObjectIdentifier key_agreement_info = new ASN1ObjectIdentifier(content_type + ".6");
}
