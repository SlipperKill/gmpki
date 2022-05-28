package com.fxal.ca.util;


import com.fxal.ca.common.api.DLL_API;
import com.fxal.ca.common.pojo.SM2Cipher;
import com.fxal.ca.common.pojo.SM2EnvelopedKey;
import com.fxal.ca.common.pojo.SM2PrivateKey;
import com.fxal.ca.common.pojo.SM2PublicKey;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import static com.fxal.ca.util.Args.notNull;

/**
 * @author caiming
 * @title: KeyUtil
 * @projectName ibk-basic
 * @description: TODO
 * @date 2019/6/5 0005下午 5:28
 */
public class KeyUtil {
    public static final ASN1ObjectIdentifier ID_SM2_PUBKEY_PARAM = new ASN1ObjectIdentifier("1.2.156.10197.1.301");


    private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

    public static SM2PublicKey convertPublicKey(DLL_API.PucPublicKey pucPublicKey) {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(pucPublicKey.x, 0, x, 0, 32);
        System.arraycopy(pucPublicKey.y, 0, y, 0, 32);
        ECPoint q = SM2Util.CURVE.createPoint(new BigInteger(1, x), new BigInteger(1, y));
        ECParameterSpec parameterSpec = new ECParameterSpec(SM2Util.CURVE, SM2Util.G_POINT,
                SM2Util.SM2_ECC_N, SM2Util.SM2_ECC_H);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, parameterSpec);
        return new SM2PublicKey(new BCECPublicKey(GMObjectIdentifiers.sm2p256v1.getId(), pubKeySpec,
                BouncyCastleProvider.CONFIGURATION));
    }

    public static SM2PrivateKey convertPrivateKey(DLL_API.PucPrivateKey pucPrivateKey) {
        byte[] k = new byte[32];
        System.arraycopy(pucPrivateKey.K, 0, k, 0, 32);
        BigInteger d = new BigInteger(1, k);
        ECParameterSpec parameterSpec = new ECParameterSpec(SM2Util.CURVE, SM2Util.G_POINT,
                SM2Util.SM2_ECC_N, SM2Util.SM2_ECC_H);
        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(d, parameterSpec);
        return new SM2PrivateKey(new BCECPrivateKey(GMObjectIdentifiers.sm2p256v1.getId(), priKeySpec, BouncyCastleProvider.CONFIGURATION));
    }

    public static DLL_API.PucPublicKey convertPublicKey(SM2PublicKey publicKey) {
        DLL_API.PucPublicKey pucPublicKey = new DLL_API.PucPublicKey();
        pucPublicKey.bits = 256;
        System.arraycopy(publicKey.getQ().getAffineXCoord().getEncoded(), 0, pucPublicKey.x, 0, 32);
        System.arraycopy(publicKey.getQ().getAffineYCoord().getEncoded(), 0, pucPublicKey.y, 0, 32);
        return pucPublicKey;
    }

    public static DLL_API.PucPublicKey convertPublicKey(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
        DLL_API.PucPublicKey pucPublicKey = new DLL_API.PucPublicKey();
        pucPublicKey.bits = 256;
        byte[] publicKeyData = publicKeyInfo.getPublicKeyData().getOctets();
        //从SubjectPublicKeyInfo中的公钥数据为65个字节，去掉首字节4
        System.arraycopy(publicKeyData, 1, pucPublicKey.x, 0, 32);
        System.arraycopy(publicKeyData, 33, pucPublicKey.y, 0, 32);
        return pucPublicKey;
    }


    public static DLL_API.ECCCipher convertECCCipher(SM2Cipher sm2Cipher) {
        DLL_API.ECCCipher pucECCCipher = new DLL_API.ECCCipher();
        System.arraycopy(sm2Cipher.getC1(), 0, pucECCCipher.x, 0, 64);
        System.arraycopy(sm2Cipher.getC1(), 64, pucECCCipher.y, 0, 64);
        System.arraycopy(sm2Cipher.getC3(), 0, pucECCCipher.M, 0, 32);
        pucECCCipher.L = sm2Cipher.getCipherText().length;
        byte[] C = sm2Cipher.getC2();
        pucECCCipher.C = C;
        return pucECCCipher;
    }

    public static SM2Cipher convertSM2Cipher(DLL_API.ECCCipher eccCipher) {
        SM2Cipher sm2Cipher = new SM2Cipher();
        byte[] c1 = new byte[128];
        System.arraycopy(eccCipher.x, 0, c1, 0, 64);
        System.arraycopy(eccCipher.y, 0, c1, 64, 64);
        sm2Cipher.setC1(c1);
        sm2Cipher.setC2(eccCipher.C);
        sm2Cipher.setC3(eccCipher.M);
        byte[] cipherText = new byte[c1.length + eccCipher.C.length + eccCipher.M.length];
        System.arraycopy(c1, 0, cipherText, 0, c1.length);
        System.arraycopy(eccCipher.C, 0, cipherText, c1.length, eccCipher.C.length);
        System.arraycopy(eccCipher.M, 0, cipherText, c1.length + eccCipher.C.length, eccCipher.M.length);
        sm2Cipher.setCipherText(cipherText);
        return sm2Cipher;
    }

    public static DLL_API.EnvelopedKeyBlob convertEnvelopedKeyBlob(SM2EnvelopedKey sm2EnvelopedKey) {
        DLL_API.EnvelopedKeyBlob cipher = new DLL_API.EnvelopedKeyBlob();
        cipher.PubKey = convertPublicKey(sm2EnvelopedKey.getSm2PublicKey());
        cipher.ECCCipherBlob = convertECCCipher(sm2EnvelopedKey.getSm2Cipher());
        System.arraycopy(sm2EnvelopedKey.getSm2EncryptedPrivateKey(), 0, cipher.cbEncryptedPriKey, 0, 64);
        cipher.ulAsymmAlgID = GMOID.SGD_SM2_3;
        cipher.ulSymmAlgID = GMOID.SGD_SM4_CBC;
        return cipher;

    }


    public static DLL_API.EnvelopedKeyBlob convertEnvelopedKeyBlob(EncryptedValue encryptedValue, SubjectPublicKeyInfo publicKeyInfo) throws IOException {
        DLL_API.EnvelopedKeyBlob cipher = new DLL_API.EnvelopedKeyBlob();
        cipher.PubKey = convertPublicKey(publicKeyInfo);
        byte[] x = new byte[64];
        byte[] y = new byte[64];
        byte[] C = new byte[16];
        byte[] M = new byte[32];
        byte[] encSymmKeyData = encryptedValue.getEncSymmKey().getOctets();
        System.arraycopy(encSymmKeyData, 0, x, 0, x.length);
        System.arraycopy(encSymmKeyData, x.length, y, 0, y.length);
        System.arraycopy(encSymmKeyData, x.length + y.length, C, 0, C.length);
        System.arraycopy(encSymmKeyData, x.length + y.length + C.length, M, 0, M.length);
        cipher.ECCCipherBlob.x = x;
        cipher.ECCCipherBlob.y = y;
        cipher.ECCCipherBlob.C = C;
        cipher.ECCCipherBlob.M = M;
        cipher.ECCCipherBlob.L = C.length;
        cipher.cbEncryptedPriKey = encryptedValue.getEncValue().getOctets();
        cipher.ulAsymmAlgID = GMOID.SGD_SM2_3;
        cipher.ulSymmAlgID = GMOID.SGD_SM4_CBC;
        return cipher;
    }

    public static SM2EnvelopedKey convertEnvelopedKey(DLL_API.EnvelopedKeyBlob envelopedKeyBlob) {
        SM2EnvelopedKey sm2EnvelopedKey = new SM2EnvelopedKey();
        sm2EnvelopedKey.setAsymmAlgID(new AlgorithmIdentifier(GMObjectIdentifiers.sm2encrypt));
        sm2EnvelopedKey.setSymmAlgID(new AlgorithmIdentifier(GMObjectIdentifiers.sms4_cbc));
        sm2EnvelopedKey.setSm2PublicKey(KeyUtil.convertPublicKey(envelopedKeyBlob.PubKey));
        sm2EnvelopedKey.setSm2Cipher(KeyUtil.convertSM2Cipher(envelopedKeyBlob.ECCCipherBlob));
        sm2EnvelopedKey.setSm2EncryptedPrivateKey(envelopedKeyBlob.cbEncryptedPriKey);
        return sm2EnvelopedKey;
    }


    public static byte[] covertSignature(DLL_API.ECCSignature pucSignature) {
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(pucSignature.r, 0, r, 0, 32);
        System.arraycopy(pucSignature.s, 0, s, 0, 32);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(new BigInteger(1, r)));
        v.add(new ASN1Integer(new BigInteger(1, s)));
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
            throws InvalidKeySpecException {
        notNull(pkInfo, "pkInfo");

        X509EncodedKeySpec keyspec;
        try {
            keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        String algorithm;
        if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
            algorithm = "RSA";
        } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
            algorithm = "DSA";
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
            algorithm = "EC";
        } else {
            algorithm = EdECConstants.getKeyAlgNameForKeyAlg(pkInfo.getAlgorithm());
        }

        if (algorithm == null) {
            throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
        }

        KeyFactory kf = getKeyFactory(algorithm);
        synchronized (kf) {
            return kf.generatePublic(keyspec);
        }
    }

    private static KeyFactory getKeyFactory(String algorithm) throws InvalidKeySpecException {
        String alg = algorithm.toUpperCase();
        if ("ECDSA".equals(alg)) {
            alg = "EC";
        }
        synchronized (KEY_FACTORIES) {
            KeyFactory kf = KEY_FACTORIES.get(algorithm);
            if (kf != null) {
                return kf;
            }

            try {
                kf = KeyFactory.getInstance(algorithm, "BC");
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm
                        + ": " + ex.getMessage());
            }
            KEY_FACTORIES.put(algorithm, kf);
            return kf;
        }
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
            throws InvalidKeyException {
        notNull(key, "key");
        if (key instanceof ECPublicKey) {
            return ECUtil.generatePublicKeyParameter(key);
        } else {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    } // method generatePublicKeyParameter

}
