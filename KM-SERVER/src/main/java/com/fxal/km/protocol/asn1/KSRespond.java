package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;

/**
 *  @author: caiming
 *  @Date: 2021/7/26 17:16
 *  @Description:
 */ 

public class KSRespond extends ASN1Object {

    private static final ASN1Integer V2 = new ASN1Integer(1);

    private ASN1Integer version;

    private EntName KMName;

    private ASN1Sequence respondList;

    private ASN1GeneralizedTime respondTime;

    private ASN1Integer taskNO;

    public static KSRespond getInstance(Object obj) {
        if (obj instanceof KSRespond) {
            return (KSRespond) obj;
        }
        if (obj != null) {
            return new KSRespond(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    protected KSRespond(ASN1Sequence seq) {
        version = V2;
        KMName = EntName.getInstance(seq.getObjectAt(1));
        respondList = ASN1Sequence.getInstance(seq.getObjectAt(2));
        respondTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
        taskNO = ASN1Integer.getInstance(seq.getObjectAt(4));
    }

    public KSRespond(EntName KMName, ASN1Sequence respondList, ASN1GeneralizedTime respondTime, ASN1Integer taskNO) {
        this.version = V2;
        this.KMName = KMName;
        this.respondList = respondList;
        this.respondTime = respondTime;
        this.taskNO = taskNO;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(KMName);
        v.add(respondList);
        v.add(respondTime);
        v.add(taskNO);
        return new DERSequence(v);
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public EntName getKMName() {
        return KMName;
    }

    public Respond[] getRespondList() {
        if (this.respondList == null) {
            return null;
        } else {
            Respond[] var1 = new Respond[this.respondList.size()];

            for(int var2 = 0; var2 < var1.length; ++var2) {
                var1[var2] = Respond.getInstance(this.respondList.getObjectAt(var2));
            }

            return var1;
        }
    }

    public ASN1GeneralizedTime getRespondTime() {
        return respondTime;
    }

    public ASN1Integer getTaskNO() {
        return taskNO;
    }
}
