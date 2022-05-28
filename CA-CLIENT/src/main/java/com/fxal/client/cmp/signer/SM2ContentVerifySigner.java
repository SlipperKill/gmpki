package com.fxal.client.cmp.signer;

import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;

/**
 *  @author: caiming
 *  @Date: 2022/5/18 15:04
 *  @Description:
 */ 

public class SM2ContentVerifySigner{

    Logger logger = LoggerFactory.getLogger(SM2ContentVerifySigner.class);

    private SubjectPublicKeyInfo publicKey;


    private BigInteger[] derDecode(byte[] encoding)
            throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() != 2) {
            return null;
        }

        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        byte[] expectedEncoding = derEncode(r, s);
        if (!Arrays.constantTimeAreEqual(expectedEncoding, encoding)) {
            return null;
        }

        return new BigInteger[]{r, s};
    }

    private byte[] derEncode(BigInteger r, BigInteger s)
            throws IOException {

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    private static byte[] toByteArray(BigInteger bi) {
        byte[] array = bi.toByteArray();
        if (array[0] == 0 && array.length > 32) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        if(array.length<32){
            byte[] tmp = new byte[32];
            System.arraycopy(array,0,tmp,tmp.length-array.length,array.length);
            array = tmp;
        }
        return array;
    }
}
