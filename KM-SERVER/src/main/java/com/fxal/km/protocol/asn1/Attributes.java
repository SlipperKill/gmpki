package com.fxal.km.protocol.asn1;

import org.bouncycastle.asn1.*;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:21
 * @Description:
 */
public class Attributes extends ASN1Object {
    private ASN1Set attributes;

    private Attributes(ASN1Set var1) {
        this.attributes = var1;
    }

    public Attributes(ASN1EncodableVector var1) {
        this.attributes = new DLSet(var1);
    }

    public static Attributes getInstance(Object var0) {
        if (var0 instanceof org.bouncycastle.asn1.cms.Attributes) {
            return (Attributes)var0;
        } else {
            return var0 != null ? new Attributes(ASN1Set.getInstance(var0)) : null;
        }
    }

    public static Attributes getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Set.getInstance(var0, var1));
    }

    public Attribute[] getAttributes() {
        Attribute[] var1 = new Attribute[this.attributes.size()];

        for(int var2 = 0; var2 != var1.length; ++var2) {
            var1[var2] = Attribute.getInstance(this.attributes.getObjectAt(var2));
        }

        return var1;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.attributes;
    }
}
