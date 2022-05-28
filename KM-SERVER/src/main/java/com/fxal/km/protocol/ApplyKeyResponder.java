package com.fxal.km.protocol;

import com.fxal.km.common.exception.KMSecurityException;
import com.fxal.km.common.util.BCECUtil;
import com.fxal.km.common.util.SM2Util;
import com.fxal.km.common.util.SM3Util;
import com.fxal.km.common.util.SM4Util;
import com.fxal.km.mgmt.service.KMMgmtService;
import com.fxal.km.mgmt.service.impl.KMMgmtServiceImpl;
import com.fxal.km.protocol.asn1.*;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;

@Component
public class ApplyKeyResponder {

    @Autowired
    private KMMgmtService kmMgmtService;

    public RetKeyRespond execute(ApplyKeyRequest applyKeyRequest, EntName caName) throws KMSecurityException {
        if (!applyKeyRequest.getAppKeyType().getAlgorithm().equals(GMObjectIdentifiers.sm_2)) {
            throw new KMSecurityException("不支持该类算法密钥对申请：" + applyKeyRequest.getAppKeyType());
        }
        if (applyKeyRequest.getAppKeyLen().getValue().compareTo(new BigInteger("256")) != 0) {
            throw new KMSecurityException("申请SM2密钥对长度须为256：" + applyKeyRequest.getAppKeyLen().getValue());
        }
        if (!applyKeyRequest.getRetSymAlg().getAlgorithm().equals(GMObjectIdentifiers.sm_4)) {
            throw new KMSecurityException("不支持该对称加密算法：" + applyKeyRequest.getRetSymAlg());
        }
        if (!applyKeyRequest.getRetAsymAlg().getAlgorithm().equals(GMObjectIdentifiers.sm_2_encrypt)) {
            throw new KMSecurityException("不支持该非对称加密算法：" + applyKeyRequest.getRetAsymAlg());
        }
        if (!applyKeyRequest.getRetHashAlg().getAlgorithm().equals(GMObjectIdentifiers.sm_3)) {
            throw new KMSecurityException("不支持该杂凑算法：" + applyKeyRequest.getRetHashAlg());
        }

        AppUserInfo appUserInfo = applyKeyRequest.getAppUserInfo();
        boolean userCertNoCheckFlag = kmMgmtService.checkUserCertNo(caName.getEntName().toString(), appUserInfo.getUserCertNo().longValueExact());
        if (!userCertNoCheckFlag) {
            throw new KMSecurityException("申请加密证书序列号重复：" + appUserInfo.getUserCertNo().longValueExact());
        }
        KeyPair keyPair = generateKeyPair();

        SubjectPublicKeyInfo retPubKey = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        SignedAndEnvelopedData retPriKey= signUserSM2PriKey(caName.getEntName().toString(),appUserInfo.getUserPubKey(),keyPair.getPrivate());
        RetKeyRespond retKeyRespond = new RetKeyRespond(appUserInfo.getUserCertNo(),retPubKey,retPriKey);
        return retKeyRespond;
    }

    private KeyPair generateKeyPair() throws KMSecurityException {
        try {
            return SM2Util.generateKeyPair();
        } catch (Exception e){
            throw new KMSecurityException("密钥产生错误："+e.getLocalizedMessage());
        }
    }

    private SignedAndEnvelopedData signUserSM2PriKey(String caName,SubjectPublicKeyInfo userPubKey,PrivateKey privateKey) throws KMSecurityException {
        try {
            byte[] secretKey = SM4Util.generateKey();

            ASN1EncodableVector recipientInfoVector = new ASN1EncodableVector();
            recipientInfoVector.add(buildRecipientInfo(secretKey,caName,userPubKey));
            RecipientInfos recipientInfos = new RecipientInfos(recipientInfoVector);

            ASN1EncodableVector digestAlgorithmVector = new ASN1EncodableVector();
            digestAlgorithmVector.add(new AlgorithmIdentifier(GMObjectIdentifiers.sm_3));
            AlgorithmIdentifiers digestAlgorithms = new AlgorithmIdentifiers(digestAlgorithmVector);
            EncryptedContentInfo encryptedContentInfo = buildEncryptedContentInfo(secretKey,privateKey);

            ASN1EncodableVector signerInfoVector = new ASN1EncodableVector();
            signerInfoVector.add(buildSignerInfo(encryptedContentInfo));
            SignerInfos signerInfos = new SignerInfos(signerInfoVector);

            return new SignedAndEnvelopedData(recipientInfos,digestAlgorithms,encryptedContentInfo,signerInfos);
        }catch (Exception e){
            e.printStackTrace();
            if(e instanceof KMSecurityException){
                throw new KMSecurityException(e.getLocalizedMessage());
            }else {
                throw new KMSecurityException("未知的系统错误：" + e.getLocalizedMessage());
            }
        }
    }

    private EncryptedContentInfo buildEncryptedContentInfo(byte[] secretKey,PrivateKey privateKey) throws KMSecurityException {
        try {
            SM2PrivateKey sm2PrivateKey = new SM2PrivateKey((BCECPrivateKey)privateKey);
            byte[] cipherText = SM4Util.encrypt_ECB_Padding(secretKey,sm2PrivateKey.getEncoded());
            AlgorithmIdentifier contentEncryptionAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_4_ecb);
            EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo(GMObjectIdentifiers.data,contentEncryptionAlgorithm,new DEROctetString(cipherText));
            return encryptedContentInfo;
        } catch (Exception e) {
            e.printStackTrace();
            throw new KMSecurityException("系统错误："+e.getLocalizedMessage());
        }
    }

    private RecipientInfo buildRecipientInfo(byte[] secretKey ,String caName,SubjectPublicKeyInfo subjectPublicKeyInfo) throws KMSecurityException {
        try {
            if(!subjectPublicKeyInfo.getAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.ecc_pub_key)){
                throw new KMSecurityException("不支持的公钥算法：" + subjectPublicKeyInfo.getAlgorithm());
            }
            BCECPublicKey publicKey = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(subjectPublicKeyInfo);
            byte[] encryptedData = SM2Util.encrypt(publicKey,secretKey);
            SM2cipher sm2cipher = SM2cipher.getInstance(SM2Util.encodeSM2CipherToDER(encryptedData));
            X509Certificate cax509Cert = kmMgmtService.getCAX509Cert(caName);
            X500Name x500Name = X500Name.getInstance(cax509Cert.getIssuerX500Principal().getEncoded());
            IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(x500Name,new ASN1Integer(cax509Cert.getSerialNumber()));
            AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_2_encrypt);
            RecipientInfo recipientInfo = new RecipientInfo(issuerAndSerialNumber, keyEncryptionAlgorithm,sm2cipher);
            return recipientInfo;
        }catch (Exception e){
            e.printStackTrace();
            throw new KMSecurityException("系统错误："+e.getLocalizedMessage());
        }
    }

    private SignerInfo buildSignerInfo(EncryptedContentInfo encryptedContentInfo) throws KMSecurityException {
        try {
            X509Certificate kmx509Cert = kmMgmtService.getKMX509Cert();
            X500Name x500Name = X500Name.getInstance(kmx509Cert.getIssuerX500Principal().getEncoded());
            IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(x500Name, new ASN1Integer(kmx509Cert.getSerialNumber()));
            byte[] hashData = SM3Util.hash(encryptedContentInfo.getEncoded());
            byte[] sign = SM2Util.sign(kmMgmtService.getKMPrivateKey(), hashData);
            AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
            AlgorithmIdentifier digestEncryptionAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_2_sign);
            ASN1OctetString encryptedDigest = new DEROctetString(sign);
            SignerInfo signerInfo = new SignerInfo(issuerAndSerialNumber,digestAlgorithm,digestEncryptionAlgorithm,encryptedDigest);
            return signerInfo;
        }catch (Exception e){
            e.printStackTrace();
            throw new KMSecurityException("系统错误："+e.getLocalizedMessage());
        }
    }
    public static void main(String args[]){
        Security.addProvider(new BouncyCastleProvider());
        KMMgmtService kmMgmtService = new KMMgmtServiceImpl();
        X509Certificate cax509Cert = kmMgmtService.getCAX509Cert(null);
        X500Name x500Name = X500Name.getInstance(cax509Cert.getIssuerX500Principal().getEncoded());
        System.out.println(x500Name);
    }

}

