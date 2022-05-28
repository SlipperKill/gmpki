package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author caiming
 * @title: EncryptedValue
 * @projectName IBK-KMC
 * @description: TODO
 * @date 2019/7/23 002310:52
 */
public class EncryptedValue extends ASN1Object {

    private AlgorithmIdentifier symmAlg;
    private DERBitString encSymmKey;
    private AlgorithmIdentifier keyAlg;
    private DERBitString encValue;

    private EncryptedValue(ASN1Sequence seq) {
        int index = 0;
        while (seq.getObjectAt(index) instanceof ASN1TaggedObject) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) seq.getObjectAt(index);

            switch (tObj.getTagNo()) {
                case 0:
                    symmAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                case 1:
                    encSymmKey = DERBitString.getInstance(tObj, false);
                    break;
                case 2:
                    keyAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown tag encountered: " + tObj.getTagNo());
            }
            index++;
        }

        encValue = DERBitString.getInstance(seq.getObjectAt(index));
    }

    public static EncryptedValue getInstance(Object o) {
        if (o instanceof org.bouncycastle.asn1.crmf.EncryptedValue) {
            return (EncryptedValue) o;
        } else if (o != null) {
            return new EncryptedValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public EncryptedValue(
            AlgorithmIdentifier symmAlg,
            DERBitString encSymmKey,
            AlgorithmIdentifier keyAlg,
            DERBitString encValue) {
        if (encValue == null) {
            throw new IllegalArgumentException("'encValue' cannot be null");
        }

        this.symmAlg = symmAlg;
        this.encSymmKey = encSymmKey;
        this.keyAlg = keyAlg;
        this.encValue = encValue;
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(false, tagNo, obj));
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        addOptional(v, 0, symmAlg);
        addOptional(v, 1, encSymmKey);
        addOptional(v, 2, keyAlg);
        v.add(encValue);
        return new DERSequence(v);
    }

    public AlgorithmIdentifier getSymmAlg() {
        return symmAlg;
    }

    public DERBitString getEncSymmKey() {
        return encSymmKey;
    }

    public AlgorithmIdentifier getKeyAlg() {
        return keyAlg;
    }

    public DERBitString getEncValue() {
        return encValue;
    }
}
