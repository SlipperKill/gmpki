package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;

/**
 *  @author: caiming
 *  @Date: 2021/7/28 16:01
 *  @Description:
 */

public class Respond extends ASN1Object implements ASN1Choice {
    public static final int TYPE_APPLY_KEY_REP = 0;
    public static final int TYPE_ERROR_PKG_REP = 3;

    private int tagNo;
    private ASN1Encodable body;

    public static Respond getInstance(Object o) {
        if (o == null || o instanceof Respond) {
            return (Respond) o;
        }

        if (o instanceof ASN1TaggedObject) {
            return new Respond((ASN1TaggedObject) o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    private Respond(ASN1TaggedObject tagged) {
        tagNo = tagged.getTagNo();
        body = getBodyForType(tagNo, tagged.getObject());
    }


    public Respond(
            int type,
            ASN1Encodable content) {
        tagNo = type;
        body = getBodyForType(type, content);
    }

    private static ASN1Encodable getBodyForType(
            int type,
            ASN1Encodable o) {
        switch (type) {
            case TYPE_APPLY_KEY_REP:
                return RetKeyRespond.getInstance(o);
            case TYPE_ERROR_PKG_REP:
                return ErrorPkgRespond.getInstance(o);
            default:
                throw new IllegalArgumentException("unknown tag number: " + type);
        }
    }

    public int getType() {
        return tagNo;
    }

    public ASN1Encodable getContent() {
        return body;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(true, tagNo, body);
    }
}
