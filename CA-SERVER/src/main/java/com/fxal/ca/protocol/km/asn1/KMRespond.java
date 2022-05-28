package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *  @author: caiming
 *  @Date: 2021/8/2 15:46
 *  @Description:
 */ 

public class KMRespond extends ASN1Object {

    private KSRespond ksRespond;
    private AlgorithmIdentifier signatureAlgorithm;
    private ASN1OctetString signatureValue;

    public static KMRespond getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KMRespond getInstance(Object obj) {
        if (obj instanceof KMRespond) {
            return (KMRespond) obj;
        }
        if (obj != null) {
            return new KMRespond(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected KMRespond(ASN1Sequence seq) {
        ksRespond = KSRespond.getInstance(seq.getObjectAt(0));
        signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        signatureValue = ASN1OctetString.getInstance(seq.getObjectAt(2));
    }

    public KMRespond(KSRespond ksRespond, AlgorithmIdentifier signatureAlgorithm, ASN1OctetString signatureValue) {
        this.ksRespond = ksRespond;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureValue = signatureValue;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(ksRespond);
        seq.add(signatureAlgorithm);
        seq.add(signatureValue);
        return new DERSequence(seq);
    }

    public KSRespond getKsRespond() {
        return ksRespond;
    }

    public ASN1OctetString getSignatureValue() {
        return signatureValue;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
