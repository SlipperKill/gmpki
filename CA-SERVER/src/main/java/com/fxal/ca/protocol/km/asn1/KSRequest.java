package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;

/**
 *  @author: caiming
 *  @Date: 2021/7/28 16:01
 *  @Description:
 */

public class KSRequest extends ASN1Object {
    private static final ASN1Integer V2 = new ASN1Integer(1);

    private ASN1Integer version;
    private EntName caName;
    private ASN1Sequence requestList;
    private ASN1GeneralizedTime requestTime;
    private ASN1Integer taskNO;

    public static KSRequest getInstance(Object obj) {
        if (obj instanceof KSRequest) {
            return (KSRequest) obj;
        }
        if (obj != null) {
            return new KSRequest(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    protected KSRequest(ASN1Sequence seq) {
        version = V2;
        caName = EntName.getInstance(seq.getObjectAt(1));
        requestList = ASN1Sequence.getInstance(seq.getObjectAt(2));
        requestTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
        taskNO = ASN1Integer.getInstance(seq.getObjectAt(4));
    }

    public KSRequest(EntName caName, ASN1Sequence requestList, ASN1GeneralizedTime requestTime, ASN1Integer taskNO) {
        this.version = V2;
        this.caName = caName;
        this.requestList = requestList;
        this.requestTime = requestTime;
        this.taskNO = taskNO;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(caName);
        v.add(requestList);
        v.add(requestTime);
        v.add(taskNO);
        return new DERSequence(v);
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public static ASN1Integer getV1() {
        return V2;
    }

    public EntName getCaName() {
        return caName;
    }


    public Request[] getRequestList() {
        if (this.requestList == null) {
            return null;
        } else {
            Request[] var1 = new Request[this.requestList.size()];

            for(int var2 = 0; var2 < var1.length; ++var2) {
                var1[var2] = Request.getInstance(this.requestList.getObjectAt(var2));
            }

            return var1;
        }
    }

    public ASN1GeneralizedTime getRequestTime() {
        return requestTime;
    }

    public ASN1Integer getTaskNO() {
        return taskNO;
    }
}
