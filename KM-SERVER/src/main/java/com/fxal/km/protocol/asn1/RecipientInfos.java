package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:57
 * @Description:
 */
public class RecipientInfos extends ASN1Object {
    private ASN1Set recipientInfo;

    private RecipientInfos(ASN1Set var1) {
        this.recipientInfo = var1;
    }

    public RecipientInfos(ASN1EncodableVector var1) {
        this.recipientInfo = new DLSet(var1);
    }

    public static RecipientInfos getInstance(Object var0) {
        if (var0 instanceof RecipientInfos) {
            return (RecipientInfos)var0;
        } else {
            return var0 != null ? new RecipientInfos(ASN1Set.getInstance(var0)) : null;
        }
    }

    public static RecipientInfos getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Set.getInstance(var0, var1));
    }



    public RecipientInfo[] getRecipientInfos() {
        RecipientInfo[] var1 = new RecipientInfo[this.recipientInfo.size()];

        for(int var2 = 0; var2 != var1.length; ++var2) {
            var1[var2] = RecipientInfo.getInstance(this.recipientInfo.getObjectAt(var2));
        }

        return var1;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.recipientInfo;
    }
}
