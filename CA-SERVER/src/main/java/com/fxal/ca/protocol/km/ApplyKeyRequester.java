package com.fxal.ca.protocol.km;

import com.baomidou.mybatisplus.extension.api.Assert;
import com.fxal.ca.cert.CertSNAllocator;
import com.fxal.ca.cert.FileSNAllocator;
import com.fxal.ca.cert.SM2CertUtil;
import com.fxal.ca.cert.SM2X509CertMaker;
import com.fxal.ca.common.exception.CASecurityException;
import com.fxal.ca.common.pojo.ApplyKeyResult;
import com.fxal.ca.mgmt.service.CAMgmtService;
import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.km.asn1.*;
import com.fxal.ca.util.*;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author: caiming
 * @Date: 2021/8/12 15:47
 * @Description:
 */
@Component
public class ApplyKeyRequester {

    private Logger logger = LoggerFactory.getLogger(ApplyKeyRequester.class);

    public static final byte[] SRC_DATA_24B = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

    @Autowired
    private CAMgmtService caMgmtService;

    public ApplyKeyResult executeRetKeyRespond(RetKeyRespond retKeyRespond) throws CASecurityException, IOException, InvalidCipherTextException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        SubjectPublicKeyInfo userPuk = retKeyRespond.getRetPubKey();
//
//                  ECPublicKeyParameters pubKey = BCECUtil.convertPublicKeyToParameters(BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(userPuk));
//            PrivateKeyInfo userPrivateKeyInfo = analyzeSignedAndEnvelopedData(retKeyRespond.getRetPriKey());
//            ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters(BCECUtil.convertPKCS8ToECPrivateKey(BCECUtil.convertECPrivateKeySEC1ToPKCS8(userPrivateKeyInfo.getPrivateKey().getOctets())));
//            logger.info("KM响应userPriKey：" + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
//            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA_24B);
//            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
//            byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
//            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
//            if (!Arrays.equals(decryptedData, SRC_DATA_24B)) {
//                logger.error("KM下发的密钥对加解密测试失败");
//            }

        ApplyKeyResult applyKeyResult = new ApplyKeyResult();
        Long userCertNo = retKeyRespond.getUserCertNo().longValueExact();
        applyKeyResult.setCertNo(userCertNo);
        applyKeyResult.setPublicKeyInfo(userPuk);
        applyKeyResult.setEncryptedValue(processSignedAndEnvelopedData(retKeyRespond.getRetPriKey()));
        return applyKeyResult;

    }

    private PrivateKeyInfo analyzeSignedAndEnvelopedData(SignedAndEnvelopedData signedAndEnvelopedData) throws CASecurityException, IOException {
        verifyEncryptedContentSign(signedAndEnvelopedData.getSignerInfos(), signedAndEnvelopedData.getEncryptedContentInfo());
        PrivateKeyInfo privateKeyInfo = decryptEncryptedContentInfo(signedAndEnvelopedData.getRecipientInfos(),signedAndEnvelopedData.getEncryptedContentInfo());
        //EncryptedValue encryptedValue = toEncryptedValue(signedAndEnvelopedData.getRecipientInfos(), signedAndEnvelopedData.getEncryptedContentInfo());
        return privateKeyInfo;
    }

    private EncryptedValue processSignedAndEnvelopedData(SignedAndEnvelopedData signedAndEnvelopedData) throws CASecurityException, IOException {
        verifyEncryptedContentSign(signedAndEnvelopedData.getSignerInfos(), signedAndEnvelopedData.getEncryptedContentInfo());
        //PrivateKeyInfo privateKeyInfo = decryptEncryptedContentInfo(signedAndEnvelopedData.getRecipientInfos(),signedAndEnvelopedData.getEncryptedContentInfo());
        EncryptedValue encryptedValue = toEncryptedValue(signedAndEnvelopedData.getRecipientInfos(), signedAndEnvelopedData.getEncryptedContentInfo());
        return encryptedValue;
    }

    public EncryptedValue toEncryptedValue(RecipientInfos recipientInfos, EncryptedContentInfo contentInfo) throws CASecurityException, IOException {
        if (recipientInfos.getRecipientInfos() == null || recipientInfos.getRecipientInfos().length == 0) {
            throw new CASecurityException("解析KM下发密钥对失败，无法获取到接收人信息");
        }
        RecipientInfo recipientInfo = recipientInfos.getRecipientInfos()[0];
        if (!recipientInfo.getKeyEncryptionAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm_2_encrypt)) {
            throw new CASecurityException("不支持的加密算法：" + recipientInfo.getKeyEncryptionAlgorithm().getAlgorithm().toString());
        }
        if (recipientInfo.getVersion().getValue().compareTo(new BigInteger("1")) != 0) {
            throw new CASecurityException("SignedAndEnvelopedData.RecipientInfo数据协议版本错误：" + recipientInfo.getVersion().getValue());
        }
        AlgorithmIdentifier symmAlg = new AlgorithmIdentifier(GMObjectIdentifiers.sm_4);
        AlgorithmIdentifier keyAlg = new AlgorithmIdentifier(GMObjectIdentifiers.sm_2);
        DERBitString encSymmKey = new DERBitString(recipientInfo.getEncryptedKey().getEncoded());
        DERBitString encValue = new DERBitString(contentInfo.getEncryptedContent().getOctets());
        EncryptedValue encryptedValue = new EncryptedValue(null, symmAlg, encSymmKey, keyAlg, null, encValue);
        return encryptedValue;
    }

    /**
     * @author: caiming
     * @Date: 2021/8/13 10:20
     * @Description: 解密加密密钥，只是测试，实际应该由用户端完成
     */

    private PrivateKeyInfo decryptEncryptedContentInfo(RecipientInfos recipientInfos, EncryptedContentInfo contentInfo) throws CASecurityException {
        try {
            for (RecipientInfo recipientInfo : recipientInfos.getRecipientInfos()) {
                if (!recipientInfo.getKeyEncryptionAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm_2_encrypt)) {
                    throw new CASecurityException("不支持的加密算法：" + recipientInfo.getKeyEncryptionAlgorithm().getAlgorithm().toString());
                }
                if (recipientInfo.getVersion().getValue().compareTo(new BigInteger("1")) != 0) {
                    throw new CASecurityException("SignedAndEnvelopedData.RecipientInfo数据协议版本错误：" + recipientInfo.getVersion().getValue());
                }
                System.out.println(recipientInfo.getEncryptedKey().getEncoded().length);
                //X509Certificate encryptCert = caMgmtService.getX509Cert(recipientInfo.getIssuerAndSerialNumber());
                byte[] secretKey = SM2Util.decrypt(getUserPrivateKey(), SM2Util.decodeDERSM2Cipher(recipientInfo.getEncryptedKey().getEncoded()));
                byte[] privateKeyData = SM4Util.decrypt_ECB_Padding(secretKey, contentInfo.getEncryptedContent().getOctets());
                PrivateKeyInfo sm2PrivateKey = PrivateKeyInfo.getInstance(privateKeyData);
                return sm2PrivateKey;
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new CASecurityException("系统错误：" + e.getLocalizedMessage());
        }
        return null;
    }

    /**
     * @author: caiming
     * @Date: 2021/8/13 10:19
     * @Description: 加密密钥响应包验签
     */

    private void verifyEncryptedContentSign(SignerInfos signerInfos, EncryptedContentInfo contentInfo) throws CASecurityException {
        try {
            for (SignerInfo signerInfo : signerInfos.getSignerInfos()) {
                if (!signerInfo.getDigestAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm_3)) {
                    throw new CASecurityException("不支持的HASH算法：" + signerInfo.getDigestAlgorithm().getAlgorithm().toString());
                }
                if (!signerInfo.getDigestEncryptionAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm_2_sign)) {
                    throw new CASecurityException("不支持的签名算法：" + signerInfo.getDigestAlgorithm().getAlgorithm().toString());
                }
                if (signerInfo.getVersion().getValue().compareTo(new BigInteger("1")) != 0) {
                    throw new CASecurityException("SignedAndEnvelopedData.SignerInfo数据协议版本错误：" + signerInfo.getVersion().getValue());
                }
                X509Certificate signCert = caMgmtService.getX509Cert(signerInfo.getIssuerAndSerialNumber());
                if (signCert == null) {
                    throw new CASecurityException("未找到对应的X509数字证书：" + signerInfo.getIssuerAndSerialNumber().toString());
                }

                BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(signCert);
                byte[] hashData = SM3Util.hash(contentInfo.getEncoded());
                boolean contentVerifySign = SM2Util.verify(pubKey, hashData, signerInfo.getEncryptedDigest().getOctets());
                if (!contentVerifySign) {
                    throw new CASecurityException("密钥加密包验签失败：");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new CASecurityException("系统错误：" + e.getLocalizedMessage());
        }
    }

    /**
     * @author: caiming
     * @Date: 2021/8/12 16:42
     * @Description: 用来测试 KM下发的密钥能否解开
     */

    private ECPrivateKeyParameters getUserPrivateKey() {
        try {
            byte[] privateKeyData = FileUtil.readFile("target/test.xx.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(privateKeyData);
            return priKeyParameters;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
