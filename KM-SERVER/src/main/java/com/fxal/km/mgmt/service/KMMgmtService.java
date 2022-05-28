package com.fxal.km.mgmt.service;

import com.fxal.km.protocol.asn1.EntName;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import java.security.cert.X509Certificate;

public interface KMMgmtService {

    public X509Certificate getCAX509Cert(String caName);

    X509Certificate getKMX509Cert();

    ECPrivateKeyParameters getKMPrivateKey();

    EntName getKMEntName();

    boolean checkUserCertNo(String caName, Long userCertNo);
}
