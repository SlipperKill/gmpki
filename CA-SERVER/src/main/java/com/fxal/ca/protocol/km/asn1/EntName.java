package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;


/**
 * @author: caiming
 * @Date: 2021/7/28 16:05
 * @Description:
 */
public class EntName extends ASN1Object {

    private AlgorithmIdentifier hashAlgorithm;

    private GeneralName entName;

    private ASN1OctetString entPubKeyHash;

    private ASN1Integer serialNumber;

    public static EntName getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EntName getInstance(Object obj) {
        if (obj instanceof CARequest) {
            return (EntName) obj;
        }
        if (obj != null) {
            return new EntName(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected EntName(ASN1Sequence seq) {
        hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        entName = GeneralName.getInstance(seq.getObjectAt(1));
        entPubKeyHash = ASN1OctetString.getInstance(seq.getObjectAt(2));
        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(3));
    }

    public EntName(AlgorithmIdentifier hashAlgorithm, GeneralName entName, ASN1OctetString entPubKeyHash, ASN1Integer serialNumber) {
        this.hashAlgorithm = hashAlgorithm;
        this.entName = entName;
        this.entPubKeyHash = entPubKeyHash;
        this.serialNumber = serialNumber;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(hashAlgorithm);
        seq.add(entName);
        seq.add(entPubKeyHash);
        seq.add(serialNumber);
        return new DERSequence(seq);
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return hashAlgorithm;
    }

    public GeneralName getEntName() {
        return entName;
    }

    public ASN1OctetString getEntPubKeyHash() {
        return entPubKeyHash;
    }

    public ASN1Integer getSerialNumber() {
        return serialNumber;
    }
}
