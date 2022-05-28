package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;

/**
 * @author: caiming
 * @Date: 2021/7/30 10:52
 * @Description:
 */
public class SignerInfos extends ASN1Object {

    private ASN1Set signerInfo;

    private SignerInfos(ASN1Set var1) {
        this.signerInfo = var1;
    }

    public SignerInfos(ASN1EncodableVector var1) {
        this.signerInfo = new DLSet(var1);
    }

    public static SignerInfos getInstance(Object var0) {
        if (var0 instanceof SignerInfos) {
            return (SignerInfos)var0;
        } else {
            return var0 != null ? new SignerInfos(ASN1Set.getInstance(var0)) : null;
        }
    }

    public static SignerInfos getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Set.getInstance(var0, var1));
    }

    public SignerInfo[] getSignerInfos() {
        SignerInfo[] var1 = new SignerInfo[this.signerInfo.size()];

        for(int var2 = 0; var2 != var1.length; ++var2) {
            var1[var2] = SignerInfo.getInstance(this.signerInfo.getObjectAt(var2));
        }

        return var1;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.signerInfo;
    }
}
