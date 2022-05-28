package com.fxal.ca.protocol.km;

import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.km.asn1.AppUserInfo;
import com.fxal.ca.protocol.km.asn1.ApplyKeyRequest;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author: caiming
 * @Date: 2021/8/10 14:11
 * @Description:
 */
public class ApplyKeyRequestBuilder {

    private AlgorithmIdentifier appKeyType = new AlgorithmIdentifier(GMObjectIdentifiers.sm_2);

    private ASN1Integer appKeyLen = new ASN1Integer(256);

    private AlgorithmIdentifier retAsymAlg = new AlgorithmIdentifier(GMObjectIdentifiers.sm_2_encrypt);
    ;

    private AlgorithmIdentifier retSymAlg = new AlgorithmIdentifier(GMObjectIdentifiers.sm_4);
    ;

    private AlgorithmIdentifier retHashAlg = new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
    ;

    private AppUserInfo appUserInfo;

    private ApplyKeyRequestBuilder() {
    }

    public ApplyKeyRequestBuilder(AppUserInfo appUserInfo) {
        this.appUserInfo = appUserInfo;
    }

    public ApplyKeyRequest build() {
        ApplyKeyRequest applyKeyRequest = new ApplyKeyRequest(appKeyType, appKeyLen, retAsymAlg, retSymAlg, retHashAlg, appUserInfo);
        return applyKeyRequest;
    }

    public void setAppKeyType(AlgorithmIdentifier appKeyType) {
        this.appKeyType = appKeyType;
    }

    public void setAppKeyLen(ASN1Integer appKeyLen) {
        this.appKeyLen = appKeyLen;
    }

    public void setRetAsymAlg(AlgorithmIdentifier retAsymAlg) {
        this.retAsymAlg = retAsymAlg;
    }

    public void setRetSymAlg(AlgorithmIdentifier retSymAlg) {
        this.retSymAlg = retSymAlg;
    }

    public void setRetHashAlg(AlgorithmIdentifier retHashAlg) {
        this.retHashAlg = retHashAlg;
    }


}
