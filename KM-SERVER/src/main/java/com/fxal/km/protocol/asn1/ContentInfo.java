package com.fxal.km.protocol.asn1;
import com.fxal.km.protocol.GMObjectIdentifiers;
import org.bouncycastle.asn1.*;

/**
 * @author: caiming
 * @Date: 2021/7/30 11:13
 * @Description:
 */
public class ContentInfo extends ASN1Object implements GMObjectIdentifiers {
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable content;

    public static ContentInfo getInstance(Object var0) {
        if (var0 instanceof ContentInfo) {
            return (ContentInfo)var0;
        } else {
            return var0 != null ? new ContentInfo(ASN1Sequence.getInstance(var0)) : null;
        }
    }

    public static ContentInfo getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Sequence.getInstance(var0, var1));
    }

    /** @deprecated */
    public ContentInfo(ASN1Sequence var1) {
        if (var1.size() >= 1 && var1.size() <= 2) {
            this.contentType = (ASN1ObjectIdentifier)var1.getObjectAt(0);
            if (var1.size() > 1) {
                ASN1TaggedObject var2 = (ASN1TaggedObject)var1.getObjectAt(1);
                if (!var2.isExplicit() || var2.getTagNo() != 0) {
                    throw new IllegalArgumentException("Bad tag for 'content'");
                }

                this.content = var2.getObject();
            }

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + var1.size());
        }
    }

    public ContentInfo(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
        this.contentType = var1;
        this.content = var2;
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public ASN1Encodable getContent() {
        return this.content;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector();
        var1.add(this.contentType);
        if (this.content != null) {
            var1.add(new DERTaggedObject(0, this.content));
        }

        return new DERSequence(var1);
    }
}
