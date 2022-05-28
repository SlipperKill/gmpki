package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

/**
 * @author: caiming
 * @Date: 2021/7/29 16:50
 * @Description:
 */
public class EncryptedContentInfo extends ASN1Object {

    private ASN1ObjectIdentifier contentType;
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private ASN1OctetString encryptedContent;
    private ASN1OctetString shareInfo1;
    private ASN1OctetString shareInfo2;

    public static EncryptedContentInfo getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EncryptedContentInfo getInstance(Object obj) {
        if (obj instanceof EncryptedContentInfo) {
            return (EncryptedContentInfo) obj;
        }
        if (obj != null) {
            return new EncryptedContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected EncryptedContentInfo(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        contentType = ASN1ObjectIdentifier.getInstance(en.nextElement());
        contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            switch (tObj.getTagNo()) {
                case 0:
                    encryptedContent = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 1:
                    shareInfo1 = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 2:
                    shareInfo2 = ASN1OctetString.getInstance(tObj, true);
                    break;
            }
        }

    }

    public EncryptedContentInfo(ASN1ObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }

    public EncryptedContentInfo(ASN1ObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm, ASN1OctetString encryptedContent) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }

    public EncryptedContentInfo(ASN1ObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm, ASN1OctetString encryptedContent, ASN1OctetString shareInfo1, ASN1OctetString shareInfo2) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
        this.shareInfo1 = shareInfo1;
        this.shareInfo2 = shareInfo2;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(contentType);
        seq.add(contentEncryptionAlgorithm);
        addOptional(seq, 0, encryptedContent);
        addOptional(seq, 1, shareInfo1);
        addOptional(seq, 2, shareInfo2);
        return new DERSequence(seq);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

    public ASN1ObjectIdentifier getContentType() {
        return contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent() {
        return encryptedContent;
    }

    public ASN1OctetString getShareInfo1() {
        return shareInfo1;
    }

    public ASN1OctetString getShareInfo2() {
        return shareInfo2;
    }
}