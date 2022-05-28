package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * @author: caiming
 * @Date: 2021/7/29 15:53
 * @Description:
 */
public class IssuerAndSerialNumber extends ASN1Object {

    private X500Name issuer;
    private ASN1Integer serialNumber;

    public static IssuerAndSerialNumber getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static IssuerAndSerialNumber getInstance(Object obj) {
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber) obj;
        }
        if (obj != null) {
            return new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected IssuerAndSerialNumber(ASN1Sequence seq) {
        issuer = X500Name.getInstance(seq.getObjectAt(0));
        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public IssuerAndSerialNumber(X500Name issuer, ASN1Integer serialNumber) {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(issuer);
        v.add(serialNumber);
        return new DERSequence(v);
    }

    public X500Name getIssuer() {
        return issuer;
    }

    public ASN1Integer getSerialNumber() {
        return serialNumber;
    }
}
