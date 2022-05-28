package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:35
 * @Description:
 */
public class SignerInfo extends ASN1Object {

    private static final ASN1Integer V2 = new ASN1Integer(1);

    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier digestAlgorithm;
    private Attributes authenticatedAttributes;
    private AlgorithmIdentifier digestEncryptionAlgorithm;
    private ASN1OctetString encryptedDigest;
    private Attributes unauthenticatedAttributes;

    public static SignerInfo getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SignerInfo getInstance(Object obj) {
        if (obj instanceof SignerInfo) {
            return (SignerInfo) obj;
        }
        if (obj != null) {
            return new SignerInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public SignerInfo(IssuerAndSerialNumber issuerAndSerialNumber, AlgorithmIdentifier digestAlgorithm, AlgorithmIdentifier digestEncryptionAlgorithm, ASN1OctetString encryptedDigest) {
        this.version = V2;
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.digestAlgorithm = digestAlgorithm;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
    }

    public SignerInfo(IssuerAndSerialNumber issuerAndSerialNumber, AlgorithmIdentifier digestAlgorithm, Attributes authenticatedAttributes, AlgorithmIdentifier digestEncryptionAlgorithm, ASN1OctetString encryptedDigest, Attributes unauthenticatedAttributes) {
        this.version = V2;
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.digestAlgorithm = digestAlgorithm;
        this.authenticatedAttributes = authenticatedAttributes;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
        this.unauthenticatedAttributes = unauthenticatedAttributes;
    }

    protected SignerInfo(ASN1Sequence var1) {
        Enumeration var2 = var1.getObjects();
        this.version = (ASN1Integer)var2.nextElement();
        this.issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(var2.nextElement());
        this.digestAlgorithm = AlgorithmIdentifier.getInstance(var2.nextElement());
        Object var3 = var2.nextElement();
        if (var3 instanceof ASN1TaggedObject) {
            this.authenticatedAttributes = Attributes.getInstance((ASN1TaggedObject)var3, true);
            this.digestEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var2.nextElement());
        } else {
            this.authenticatedAttributes = null;
            this.digestEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var3);
        }

        this.encryptedDigest = DEROctetString.getInstance(var2.nextElement());
        if (var2.hasMoreElements()) {
            this.unauthenticatedAttributes = Attributes.getInstance((ASN1TaggedObject)var2.nextElement(), true);
        } else {
            this.unauthenticatedAttributes = null;
        }

    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector();
        var1.add(this.version);
        var1.add(this.issuerAndSerialNumber);
        var1.add(this.digestAlgorithm);
        if (this.authenticatedAttributes != null) {
            var1.add(new DERTaggedObject(true, 0, this.authenticatedAttributes));
        }

        var1.add(this.digestEncryptionAlgorithm);
        var1.add(this.encryptedDigest);
        if (this.unauthenticatedAttributes != null) {
            var1.add(new DERTaggedObject(true, 1, this.unauthenticatedAttributes));
        }

        return new DERSequence(var1);
    }
}
