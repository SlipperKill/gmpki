package com.fxal.ca.mgmt.service.impl;

import com.fxal.ca.cert.SM2CertUtil;
import com.fxal.ca.mgmt.CaMgmtException;
import com.fxal.ca.mgmt.service.CAMgmtService;
import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.km.asn1.EntName;
import com.fxal.ca.protocol.km.asn1.IssuerAndSerialNumber;
import com.fxal.ca.util.BCECUtil;
import com.fxal.ca.util.FileUtil;
import com.fxal.ca.util.SM3Util;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author: caiming
 * @Date: 2021/8/10 14:47
 * @Description:
 *
 * 此服务应该对接管理系统，从管理系统或数据库中获取相应数据
 * 此处为了方便测试，暂时写死数据
 */
@Service
public class CAMgmtServiceImpl implements CAMgmtService {

    @Override
    public X509Certificate getCAX509Cert() {
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.root.ca.cer");
            return cert;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public X500Name getIssuer(){
        X509Certificate CaCert = getCAX509Cert();
        X500Name issuer = X500Name.getInstance(CaCert.getIssuerX500Principal().getEncoded());
        return issuer;
    }

    @Override
    public ECPrivateKeyParameters getCAPrivateKeyParameters(){
        try {
            byte[] privateKeyData = FileUtil.readFile("src/main/resources/certs/test.root.ca.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(privateKeyData);
            return priKeyParameters;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public PrivateKey getCAPrivateKey(){
        try {
            byte[] privateKeyData = FileUtil.readFile("src/main/resources/certs/test.root.ca.pri");
            PrivateKey privateKey = BCECUtil.convertSEC1ToBCECPrivateKey(privateKeyData);
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public KeyPair getCaKeyPair(){
        KeyPair caKeyPair = new KeyPair(getCAX509Cert().getPublicKey(),getCAPrivateKey());
        return caKeyPair;
    }

    @Override
    public X509Certificate getKMX509Cert(String kmName) {
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.sm2.cer");
            return cert;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public EntName getCAEntName(){
        X509Certificate CaCert = getCAX509Cert();
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
        X500Name x500Name = X500Name.getInstance(CaCert.getIssuerX500Principal().getEncoded());
        GeneralName entName = new GeneralName(x500Name);
        ASN1OctetString entPubKeyHash = new DEROctetString(SM3Util.hash(CaCert.getPublicKey().getEncoded()));
        ASN1Integer serialNumber = new ASN1Integer(CaCert.getSerialNumber());
        EntName KMEntName = new EntName(hashAlgorithm,entName,entPubKeyHash,serialNumber);
        return KMEntName;
    }

    @Override
    public X509Certificate getX509Cert(X500Name issuer, BigInteger serialNumber) throws CaMgmtException {
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.sm2.cer");
            return cert;
        }catch (Exception e){
            e.printStackTrace();
            throw new CaMgmtException("get cert fail:"+e.getLocalizedMessage());
        }

    }

    @Override
    public X509Certificate getX509Cert(IssuerAndSerialNumber issuerAndSerialNumber){
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.sm2.cer");
            return cert;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public X509Certificate getX509Cert(String x500Name ){
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.user.cer");
            return cert;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean checkCertRevoked(X509Certificate cert){
        return false;
    }

    @Override
    public boolean checkIsRa(String x500Name){
        return true;
    }

    @Override
    public X500Name buildCaDN(String identity) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, identity);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.vargo");
        builder.addRDN(BCStyle.OU, "org.vargo");
        return builder.build();
    }

//    @Override
//    public SM2X509CertMaker buildCertMaker() {
//        BCECPrivateKey
//        KeyPair caKeyPair = new KeyPair(getCAX509Cert().getPublicKey(),getCAPrivateKey());
//            X500Name issuerName = buildRootCADN();
//            CertSNAllocator snAllocator = new FileSNAllocator(); // 实际应用中可能需要使用数据库来维护证书序列号
//            SM2X509CertMaker certMaker = new SM2X509CertMaker(getTIADeviceType(), masterPublicKey, issuerName, snAllocator);
//            return certMaker;
//    }
}
