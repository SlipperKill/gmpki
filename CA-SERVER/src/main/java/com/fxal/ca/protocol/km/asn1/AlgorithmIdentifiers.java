package com.fxal.ca.protocol.km.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author: caiming
 * @Date: 2021/7/30 11:01
 * @Description:
 */
public class AlgorithmIdentifiers extends ASN1Object {

    private ASN1Set algorithmIdentifier;

    private AlgorithmIdentifiers(ASN1Set var1) {
        this.algorithmIdentifier = var1;
    }

    public AlgorithmIdentifiers(ASN1EncodableVector var1) {
        this.algorithmIdentifier = new DLSet(var1);
    }

    public static AlgorithmIdentifiers getInstance(Object var0) {
        if (var0 instanceof AlgorithmIdentifiers) {
            return (AlgorithmIdentifiers)var0;
        } else {
            return var0 != null ? new AlgorithmIdentifiers(ASN1Set.getInstance(var0)) : null;
        }
    }

    public static AlgorithmIdentifiers getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Set.getInstance(var0, var1));
    }

    public AlgorithmIdentifier[] getAlgorithmIdentifiers() {
        AlgorithmIdentifier[] var1 = new AlgorithmIdentifier[this.algorithmIdentifier.size()];

        for(int var2 = 0; var2 != var1.length; ++var2) {
            var1[var2] = AlgorithmIdentifier.getInstance(this.algorithmIdentifier.getObjectAt(var2));
        }

        return var1;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.algorithmIdentifier;
    }
}
