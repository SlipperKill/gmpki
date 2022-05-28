package com.fxal.ca.protocol.km;

import com.fxal.ca.protocol.km.asn1.EntName;
import com.fxal.ca.protocol.km.asn1.KSRequest;
import com.fxal.ca.protocol.km.asn1.Request;
import com.fxal.ca.util.Args;
import org.bouncycastle.asn1.*;

import java.util.Date;
import java.util.List;

/**
 * @author: caiming
 * @Date: 2021/8/10 14:29
 * @Description:
 */
public class KSRequestBuilder {

    private EntName caName;
    private ASN1Sequence requestList;
    private ASN1GeneralizedTime requestTime = new ASN1GeneralizedTime(new Date());
    private ASN1Integer taskNO;

    public KSRequestBuilder(EntName caName) {
        this.caName = caName;
    }

    private KSRequestBuilder() {
    }

    public KSRequest build(){
        Args.notNull(requestList,"requestList");
        Args.notNull(taskNO,"taskNO");
        KSRequest ksRequest = new KSRequest(caName,requestList,requestTime,taskNO);
        return ksRequest;
    }


    public void setRequestList(List<Request> requestList) {
        ASN1EncodableVector requests = new ASN1EncodableVector();
        for(Request request:requestList){
            requests.add(request);
        }
        this.requestList = new DERSequence(requests);
    }

    public void setRequestTime(ASN1GeneralizedTime requestTime) {
        this.requestTime = requestTime;
    }

    public void setTaskNO(Long taskNO) {
        this.taskNO = new ASN1Integer(taskNO);
    }
}
