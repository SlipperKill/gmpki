package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;

/**
 *  @author: caiming
 *  @Date: 2021/8/2 15:43
 *  @Description:
 */ 

public class ErrorPkgRespond extends ASN1Object {
    private DERUTF8String errCode;
    private DERUTF8String errDesc;

    public static ErrorPkgRespond getInstance(Object obj) {
        if (obj instanceof ErrorPkgRespond) {
            return (ErrorPkgRespond) obj;
        }
        if (obj != null) {
            return new ErrorPkgRespond(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    protected ErrorPkgRespond(ASN1Sequence seq) {
        errCode = DERUTF8String.getInstance(seq.getObjectAt(0));
        errDesc = DERUTF8String.getInstance(seq.getObjectAt(1));
    }

    public ErrorPkgRespond(DERUTF8String errCode, DERUTF8String errDesc) {
        this.errCode = errCode;
        this.errDesc = errDesc;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(errCode);
        v.add(errDesc);
        return new DERSequence(v);
    }

    public DERUTF8String getErrCode() {
        return errCode;
    }

    public DERUTF8String getErrDesc() {
        return errDesc;
    }
}
