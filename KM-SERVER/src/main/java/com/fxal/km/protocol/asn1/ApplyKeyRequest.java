package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

/**
 *  @author: caiming
 *  @Date: 2021/8/2 15:35
 *  @Description:
 */ 

public class ApplyKeyRequest extends ASN1Object {

    private AlgorithmIdentifier appKeyType;

    private ASN1Integer appKeyLen;

    private AlgorithmIdentifier retAsymAlg;

    private AlgorithmIdentifier retSymAlg;

    private AlgorithmIdentifier retHashAlg;

    private AppUserInfo appUserInfo;

    public static ApplyKeyRequest getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ApplyKeyRequest getInstance(Object obj) {
        if (obj instanceof ApplyKeyRequest) {
            return (ApplyKeyRequest) obj;
        }
        if (obj != null) {
            return new ApplyKeyRequest(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected ApplyKeyRequest(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        appKeyType = AlgorithmIdentifier.getInstance(en.nextElement());
        appKeyLen = ASN1Integer.getInstance(en.nextElement());
        retAsymAlg = AlgorithmIdentifier.getInstance(en.nextElement());
        retSymAlg = AlgorithmIdentifier.getInstance(en.nextElement());
        retHashAlg = AlgorithmIdentifier.getInstance(en.nextElement());
        appUserInfo = AppUserInfo.getInstance(en.nextElement());

    }

    public ApplyKeyRequest(AlgorithmIdentifier appKeyType, ASN1Integer appKeyLen, AlgorithmIdentifier retAsymAlg, AlgorithmIdentifier retSymAlg, AlgorithmIdentifier retHashAlg, AppUserInfo appUserInfo) {
        this.appKeyType = appKeyType;
        this.appKeyLen = appKeyLen;
        this.retAsymAlg = retAsymAlg;
        this.retSymAlg = retSymAlg;
        this.retHashAlg = retHashAlg;
        this.appUserInfo = appUserInfo;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(appKeyType);
        seq.add(appKeyLen);
        seq.add(retAsymAlg);
        seq.add(retSymAlg);
        seq.add(retHashAlg);
        seq.add(appUserInfo);
        return new DERSequence(seq);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

    public AlgorithmIdentifier getAppKeyType() {
        return appKeyType;
    }

    public ASN1Integer getAppKeyLen() {
        return appKeyLen;
    }

    public AlgorithmIdentifier getRetAsymAlg() {
        return retAsymAlg;
    }

    public AlgorithmIdentifier getRetSymAlg() {
        return retSymAlg;
    }

    public AlgorithmIdentifier getRetHashAlg() {
        return retHashAlg;
    }

    public AppUserInfo getAppUserInfo() {
        return appUserInfo;
    }
}
