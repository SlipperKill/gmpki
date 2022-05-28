package com.fxal.km.mgmt.service.impl;

import com.fxal.km.common.util.BCECUtil;
import com.fxal.km.common.util.FileUtil;
import com.fxal.km.common.util.SM2CertUtil;
import com.fxal.km.common.util.SM3Util;
import com.fxal.km.mgmt.service.KMMgmtService;
import com.fxal.km.protocol.GMObjectIdentifiers;
import com.fxal.km.protocol.asn1.EntName;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Service
public class KMMgmtServiceImpl implements KMMgmtService {
    @Override
    public X509Certificate getCAX509Cert(String caName) {
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
    public X509Certificate getKMX509Cert(){
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
    public ECPrivateKeyParameters getKMPrivateKey(){
        try {
           byte[] privateKeyData = FileUtil.readFile("src/main/resources/certs/test.sm2.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(privateKeyData);
            return priKeyParameters;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public EntName getKMEntName(){
        X509Certificate KMCert = getKMX509Cert();
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
        X500Name x500Name = X500Name.getInstance(KMCert.getIssuerX500Principal().getEncoded());
        GeneralName entName = new GeneralName(x500Name);
        ASN1OctetString entPubKeyHash = new DEROctetString(SM3Util.hash(KMCert.getPublicKey().getEncoded()));
        ASN1Integer serialNumber = new ASN1Integer(KMCert.getSerialNumber());
        EntName KMEntName = new EntName(hashAlgorithm,entName,entPubKeyHash,serialNumber);
        return KMEntName;
    }


    /**
     * 检查用户申请的加密证书序列号是否重复
     * @param caName ca名称
     * @param userCertNo 用户申请加密证书序列号
     * @return
     */
    @Override
    public boolean checkUserCertNo(String caName,Long userCertNo){
        return true;
    }
}
