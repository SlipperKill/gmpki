package com.fxal.ca.common.pojo;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author caiming
 * @title: SM2EnvelopedKey
 * @projectName ibk-cert-sign
 * @description: TODO
 * @date 2019/6/14 0014下午 5:17
 */
public class SM2EnvelopedKey {
    private AlgorithmIdentifier asymmAlgID;
    private AlgorithmIdentifier symmAlgID;
    private SM2PublicKey sm2PublicKey;
    private byte[] sm2EncryptedPrivateKey;
    private SM2Cipher sm2Cipher;

    public AlgorithmIdentifier getAsymmAlgID() {
        return asymmAlgID;
    }

    public void setAsymmAlgID(AlgorithmIdentifier asymmAlgID) {
        this.asymmAlgID = asymmAlgID;
    }

    public AlgorithmIdentifier getSymmAlgID() {
        return symmAlgID;
    }

    public void setSymmAlgID(AlgorithmIdentifier symmAlgID) {
        this.symmAlgID = symmAlgID;
    }

    public SM2PublicKey getSm2PublicKey() {
        return sm2PublicKey;
    }

    public void setSm2PublicKey(SM2PublicKey sm2PublicKey) {
        this.sm2PublicKey = sm2PublicKey;
    }

    public byte[] getSm2EncryptedPrivateKey() {
        return sm2EncryptedPrivateKey;
    }

    public void setSm2EncryptedPrivateKey(byte[] sm2EncryptedPrivateKey) {
        this.sm2EncryptedPrivateKey = sm2EncryptedPrivateKey;
    }

    public SM2Cipher getSm2Cipher() {
        return sm2Cipher;
    }

    public void setSm2Cipher(SM2Cipher sm2Cipher) {
        this.sm2Cipher = sm2Cipher;
    }
}
