package com.fxal.ca.mgmt.service;

import com.fxal.ca.mgmt.CaMgmtException;
import com.fxal.ca.protocol.km.asn1.EntName;
import com.fxal.ca.protocol.km.asn1.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author: caiming
 * @Date: 2021/8/10 14:46
 * @Description:
 */
public interface CAMgmtService {
    X509Certificate getCAX509Cert();

    X500Name getIssuer();

    ECPrivateKeyParameters getCAPrivateKeyParameters();

    abstract PrivateKey getCAPrivateKey();

    KeyPair getCaKeyPair();

    X509Certificate getKMX509Cert(String kmName);

    EntName getCAEntName();

    X509Certificate getX509Cert(X500Name issuer, BigInteger serialNumber) throws CaMgmtException;

    X509Certificate getX509Cert(IssuerAndSerialNumber issuerAndSerialNumber);

    X509Certificate getX509Cert(String x500Name);

    boolean checkCertRevoked(X509Certificate cert);

    boolean checkIsRa(String x500Name);

    X500Name buildCaDN(String identity);
}
