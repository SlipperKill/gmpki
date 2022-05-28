package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:31
 * @Description:
 */
public class ExtendedCertificateOrCertificates extends ASN1Object {

    private ASN1Set extendedCertificateOrCertificate;

    private ExtendedCertificateOrCertificates(ASN1Set var1) {
        this.extendedCertificateOrCertificate = var1;
    }

    public ExtendedCertificateOrCertificates(ASN1EncodableVector var1) {
        this.extendedCertificateOrCertificate = new DLSet(var1);
    }

    public static ExtendedCertificateOrCertificates getInstance(Object var0) {
        if (var0 instanceof org.bouncycastle.asn1.cms.Attributes) {
            return (ExtendedCertificateOrCertificates)var0;
        } else {
            return var0 != null ? new ExtendedCertificateOrCertificates(ASN1Set.getInstance(var0)) : null;
        }
    }

    public static ExtendedCertificateOrCertificates getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Set.getInstance(var0, var1));
    }

    public ExtendedCertificateOrCertificate[] getExtendedCertificateOrCertificates() {
        ExtendedCertificateOrCertificate[] var1 = new ExtendedCertificateOrCertificate[this.extendedCertificateOrCertificate.size()];

        for(int var2 = 0; var2 != var1.length; ++var2) {
            var1[var2] = ExtendedCertificateOrCertificate.getInstance(this.extendedCertificateOrCertificate.getObjectAt(var2));
        }

        return var1;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.extendedCertificateOrCertificate;
    }
}
