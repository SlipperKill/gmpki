package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 *  @author: caiming
 *  @Date: 2021/7/30 15:24
 *  @Description:
 */

public class RetKeyRespond extends ASN1Object {

    private ASN1Integer userCertNo;
    private SubjectPublicKeyInfo retPubKey;
    private SignedAndEnvelopedData retPriKey;


    public static RetKeyRespond getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RetKeyRespond getInstance(Object obj) {
        if (obj instanceof RetKeyRespond) {
            return (RetKeyRespond) obj;
        }
        if (obj != null) {
            return new RetKeyRespond(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected RetKeyRespond(ASN1Sequence seq) {
        userCertNo = ASN1Integer.getInstance(seq.getObjectAt(0));
        retPubKey = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(1));
        retPriKey = SignedAndEnvelopedData.getInstance(seq.getObjectAt(2));
    }

    public RetKeyRespond(ASN1Integer userCertNo, SubjectPublicKeyInfo retPubKey, SignedAndEnvelopedData retPriKey) {
        this.userCertNo = userCertNo;
        this.retPubKey = retPubKey;
        this.retPriKey = retPriKey;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(userCertNo);
        v.add(retPubKey);
        v.add(retPriKey);
        return new DERSequence(v);
    }

    public ASN1Integer getUserCertNo() {
        return userCertNo;
    }

    public SubjectPublicKeyInfo getRetPubKey() {
        return retPubKey;
    }

    public SignedAndEnvelopedData getRetPriKey() {
        return retPriKey;
    }
}
