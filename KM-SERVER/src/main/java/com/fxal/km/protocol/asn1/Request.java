package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;

/**
 *  @author: caiming
 *  @Date: 2021/8/2 15:49
 *  @Description:
 */ 

public class Request extends ASN1Object implements ASN1Choice {

    public static final int TYPE_APPLY_KEY_REQ = 0;
    public static final int TYPE_RESTORE_KEY_REQ = 1;
    public static final int TYPE_REVOKE_KEY_REQ = 2;

    private int tagNo;
    private ASN1Encodable body;

    public static Request getInstance(Object o) {
        if (o == null || o instanceof Request) {
            return (Request) o;
        }

        if (o instanceof ASN1TaggedObject) {
            return new Request((ASN1TaggedObject) o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    private Request(ASN1TaggedObject tagged) {
        tagNo = tagged.getTagNo();
        body = getBodyForType(tagNo, tagged.getObject());
    }


    public Request(
            int type,
            ASN1Encodable content) {
        tagNo = type;
        body = getBodyForType(type, content);
    }

    private static ASN1Encodable getBodyForType(
            int type,
            ASN1Encodable o) {
        switch (type) {
            case TYPE_APPLY_KEY_REQ:
                return ApplyKeyRequest.getInstance(o);

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
