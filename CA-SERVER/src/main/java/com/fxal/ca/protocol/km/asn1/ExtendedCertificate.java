package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:12
 * @Description:
 */
public class ExtendedCertificate extends ASN1Object {

    private ExtendedCertificateInfo extendedCertificateInfo;
    private AlgorithmIdentifier signatureAlgorithm;
    private DERBitString signature;

    public static ExtendedCertificate getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ExtendedCertificate getInstance(Object obj) {
        if (obj instanceof RecipientInfo) {
            return (ExtendedCertificate) obj;
        }
        if (obj != null) {
            return new ExtendedCertificate(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected ExtendedCertificate(ASN1Sequence seq) {
        extendedCertificateInfo = ExtendedCertificateInfo.getInstance(seq.getObjectAt(0));
        signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        signature = DERBitString.getInstance(seq.getObjectAt(2));
    }



    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(extendedCertificateInfo);
        v.add(signatureAlgorithm);
        v.add(signature);
        return new DERSequence(v);
    }
}
