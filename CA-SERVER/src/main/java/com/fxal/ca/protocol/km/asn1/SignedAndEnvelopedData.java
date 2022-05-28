package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:56
 * @Description:
 */
public class SignedAndEnvelopedData extends ASN1Object {

    private static final ASN1Integer V2 = new ASN1Integer(1);

    private ASN1Integer version;
    private RecipientInfos recipientInfos;
    private AlgorithmIdentifiers digestAlgorithms;
    private EncryptedContentInfo encryptedContentInfo;
    private ExtendedCertificateOrCertificates certificates;
    private CertificateRevocationLists crls;
    private SignerInfos signerInfos;

    public static SignedAndEnvelopedData getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SignedAndEnvelopedData getInstance(Object obj) {
        if (obj instanceof SignedAndEnvelopedData) {
            return (SignedAndEnvelopedData) obj;
        }
        if (obj != null) {
            return new SignedAndEnvelopedData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }



    protected SignedAndEnvelopedData(ASN1Sequence var1) {
        Enumeration var2 = var1.getObjects();
        this.version = (ASN1Integer)var2.nextElement();
        this.recipientInfos = RecipientInfos.getInstance(var2.nextElement());
        this.digestAlgorithms = AlgorithmIdentifiers.getInstance(var2.nextElement());
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(var2.nextElement());
        Object var3 = var2.nextElement();
        if (var3 instanceof ASN1TaggedObject) {
            if(((ASN1TaggedObject) var3).getTagNo()==0){
                this.certificates = ExtendedCertificateOrCertificates.getInstance((ASN1TaggedObject)var3, true);
                Object var4 = var2.nextElement();
                if(var4 instanceof ASN1TaggedObject){
                    this.crls = CertificateRevocationLists.getInstance((ASN1TaggedObject)var4, true);
                }else{
                    this.signerInfos = SignerInfos.getInstance(var4);
                }
            }else {
                this.certificates = null;
                this.crls = CertificateRevocationLists.getInstance((ASN1TaggedObject)var3, true);
                this.signerInfos = SignerInfos.getInstance(var2.nextElement());
            }
        }else{
            this.signerInfos = SignerInfos.getInstance(var3);
        }

    }

    public SignedAndEnvelopedData(RecipientInfos recipientInfos, AlgorithmIdentifiers digestAlgorithms, EncryptedContentInfo encryptedContentInfo, ExtendedCertificateOrCertificates certificates, CertificateRevocationLists crls, SignerInfos signerInfos) {
        this.version = V2;
        this.recipientInfos = recipientInfos;
        this.digestAlgorithms = digestAlgorithms;
        this.encryptedContentInfo = encryptedContentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
    }

    public SignedAndEnvelopedData(RecipientInfos recipientInfos, AlgorithmIdentifiers digestAlgorithms, EncryptedContentInfo encryptedContentInfo, SignerInfos signerInfos) {
        this.version = V2;
        this.recipientInfos = recipientInfos;
        this.digestAlgorithms = digestAlgorithms;
        this.encryptedContentInfo = encryptedContentInfo;
        this.signerInfos = signerInfos;
    }

    public ASN1Integer getVersion() {
        return V2;
    }

    public RecipientInfos getRecipientInfos() {
        return recipientInfos;
    }

    public AlgorithmIdentifiers getDigestAlgorithms() {
        return digestAlgorithms;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }

    public ExtendedCertificateOrCertificates getCertificates() {
        return certificates;
    }

    public CertificateRevocationLists getCrls() {
        return crls;
    }

    public SignerInfos getSignerInfos() {
        return signerInfos;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector();
        var1.add(this.version);
        var1.add(this.recipientInfos);
        var1.add(this.digestAlgorithms);
        var1.add(this.encryptedContentInfo);
        if (this.certificates != null) {
            var1.add(new DERTaggedObject(true, 0, this.certificates));
        }
        if (this.crls != null) {
            var1.add(new DERTaggedObject(true, 1, this.crls));
        }

        var1.add(this.signerInfos);
        return new DERSequence(var1);
    }


}
