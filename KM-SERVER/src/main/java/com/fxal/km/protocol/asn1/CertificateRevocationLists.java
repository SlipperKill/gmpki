package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.CertificateList;

/**
 * @author: caiming
 * @Date: 2021/7/30 14:32
 * @Description:
 */
public class CertificateRevocationLists extends ASN1Object {

    private ASN1Set certificateRevocationList;

    private CertificateRevocationLists(ASN1Set var1) {
        this.certificateRevocationList = var1;
    }

    public CertificateRevocationLists(ASN1EncodableVector var1) {
        this.certificateRevocationList = new DLSet(var1);
    }

    public static CertificateRevocationLists getInstance(Object var0) {
        if (var0 instanceof CertificateRevocationLists) {
            return (CertificateRevocationLists)var0;
        } else {
            return var0 != null ? new CertificateRevocationLists(ASN1Set.getInstance(var0)) : null;
        }
    }

    public static CertificateRevocationLists getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Set.getInstance(var0, var1));
    }

    public CertificateList[] getCertificateRevocationLists() {
        CertificateList[] var1 = new CertificateList[this.certificateRevocationList.size()];

        for(int var2 = 0; var2 != var1.length; ++var2) {
            var1[var2] = CertificateList.getInstance(this.certificateRevocationList.getObjectAt(var2));
        }

        return var1;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.certificateRevocationList;
    }
}
