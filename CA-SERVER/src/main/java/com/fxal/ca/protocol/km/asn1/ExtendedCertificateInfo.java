package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * @author: caiming
 * @Date: 2021/7/30 9:53
 * @Description:
 */
public class ExtendedCertificateInfo extends ASN1Object {
    private static final ASN1Integer V1 = new ASN1Integer(0);

    private ASN1Integer version;
    private Certificate certificate;
    private Attributes attributes;

    public static ExtendedCertificateInfo getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ExtendedCertificateInfo getInstance(Object obj) {
        if (obj instanceof RecipientInfo) {
            return (ExtendedCertificateInfo) obj;
        }
        if (obj != null) {
            return new ExtendedCertificateInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected ExtendedCertificateInfo(ASN1Sequence seq) {
        version = V1;
        certificate = Certificate.getInstance(seq.getObjectAt(0));
        attributes = Attributes.getInstance(seq.getObjectAt(1));
    }

    public ExtendedCertificateInfo(Certificate certificate, Attributes attributes) {
        this.version = V1;
        this.certificate = certificate;
        this.attributes = attributes;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(certificate);
        v.add(attributes);
        return new DERSequence(v);
    }
}
