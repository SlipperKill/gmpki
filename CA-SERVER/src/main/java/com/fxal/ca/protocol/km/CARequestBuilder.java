package com.fxal.ca.protocol.km;

import com.fxal.ca.common.exception.CASecurityException;
import com.fxal.ca.mgmt.service.CAMgmtService;
import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.km.asn1.CARequest;
import com.fxal.ca.protocol.km.asn1.KSRequest;
import com.fxal.ca.util.SM2Util;
import com.fxal.ca.util.SM3Util;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;


/**
 * @author: caiming
 * @Date: 2021/8/10 13:56
 * @Description:
 */
public class CARequestBuilder {

    private KSRequest ksRequest;

    private ECPrivateKeyParameters CAPrivateKey;


    private CARequestBuilder() {
    }

    public CARequestBuilder(final KSRequest ksRequest) {
        this.ksRequest = ksRequest;
    }

    public void setCAPrivateKey(ECPrivateKeyParameters CAPrivateKey) {
        this.CAPrivateKey = CAPrivateKey;
    }

    public CARequest build() throws CASecurityException {
        try {
            byte[] hashData = SM3Util.hash(ksRequest.getEncoded());
            byte[] sign = SM2Util.sign(CAPrivateKey, hashData);
            AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm2_with_sm3);
            ASN1OctetString signatureValue = new DEROctetString(sign);
            CARequest caRequest = new CARequest(ksRequest,signatureAlgorithm,signatureValue);
            return caRequest;
        }catch (Exception e){
            e.printStackTrace();
            throw new CASecurityException("CARequest签名错误：" + e.getLocalizedMessage());
        }
    }
}
