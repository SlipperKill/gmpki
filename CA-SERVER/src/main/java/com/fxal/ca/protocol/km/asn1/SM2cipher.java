package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;

/**
 * @author: caiming
 * @Date: 2021/7/29 16:02
 * @Description:
 */
public class SM2cipher extends ASN1Object {

    private ASN1Integer XCoordinate;
    private ASN1Integer yCoordinate;
    private ASN1OctetString HASH;
    private ASN1OctetString CipherText;

    public static SM2cipher getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SM2cipher getInstance(Object obj) {
        if (obj instanceof SM2cipher) {
            return (SM2cipher) obj;
        }
        if (obj != null) {
            return new SM2cipher(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected SM2cipher(ASN1Sequence seq) {
        XCoordinate = ASN1Integer.getInstance(seq.getObjectAt(0));
        yCoordinate = ASN1Integer.getInstance(seq.getObjectAt(1));
        HASH = ASN1OctetString.getInstance(seq.getObjectAt(2));
        CipherText = ASN1OctetString.getInstance(seq.getObjectAt(3));
    }

    public SM2cipher(ASN1Integer XCoordinate, ASN1Integer yCoordinate, ASN1OctetString HASH, ASN1OctetString cipherText) {
        this.XCoordinate = XCoordinate;
        this.yCoordinate = yCoordinate;
        this.HASH = HASH;
        CipherText = cipherText;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(XCoordinate);
        v.add(yCoordinate);
        v.add(HASH);
        v.add(CipherText);
        return new DERSequence(v);
    }

    public ASN1Integer getXCoordinate() {
        return XCoordinate;
    }

    public ASN1Integer getyCoordinate() {
        return yCoordinate;
    }

    public ASN1OctetString getHASH() {
        return HASH;
    }

    public ASN1OctetString getCipherText() {
        return CipherText;
    }
}
