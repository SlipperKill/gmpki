package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Certificate;

import java.util.Enumeration;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:24
 * @Description:
 */
public class ExtendedCertificateOrCertificate extends ASN1Object {

    private Certificate certificate;
    private ExtendedCertificate extendedCertificate;

    public static ExtendedCertificateOrCertificate getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ExtendedCertificateOrCertificate getInstance(Object obj) {
        if (obj instanceof EncryptedContentInfo) {
            return (ExtendedCertificateOrCertificate) obj;
        }
        if (obj != null) {
            return new ExtendedCertificateOrCertificate(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected ExtendedCertificateOrCertificate(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        certificate = Certificate.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            switch (tObj.getTagNo()) {
                case 0:
                    extendedCertificate = ExtendedCertificate.getInstance(tObj, true);
                    break;
            }
        }

    }

    public ExtendedCertificateOrCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public ExtendedCertificateOrCertificate(Certificate certificate, ExtendedCertificate extendedCertificate) {
        this.certificate = certificate;
        this.extendedCertificate = extendedCertificate;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(certificate);
        addOptional(seq, 0, extendedCertificate);
        return new DERSequence(seq);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(false, tagNo, obj));
        }
    }
}
