package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author: caiming
 * @Date: 2021/7/29 16:07
 * @Description:
 */
public class RecipientInfo extends ASN1Object {

    private static final ASN1Integer V2 = new ASN1Integer(1);

    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private SM2cipher encryptedKey;

    public static RecipientInfo getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RecipientInfo getInstance(Object obj) {
        if (obj instanceof RecipientInfo) {
            return (RecipientInfo) obj;
        }
        if (obj != null) {
            return new RecipientInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected RecipientInfo(ASN1Sequence seq) {
        version = V2;
        issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(seq.getObjectAt(1));
        keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        encryptedKey = SM2cipher.getInstance(seq.getObjectAt(3));
    }

    public RecipientInfo(IssuerAndSerialNumber issuerAndSerialNumber, AlgorithmIdentifier keyEncryptionAlgorithm, SM2cipher encryptedKey) {
        this.version = V2;
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }

    public ASN1Integer getVersion() {
        return V2;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(issuerAndSerialNumber);
        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKey);
        return new DERSequence(v);
    }

    public SM2cipher getEncryptedKey() {
        return encryptedKey;
    }
}
