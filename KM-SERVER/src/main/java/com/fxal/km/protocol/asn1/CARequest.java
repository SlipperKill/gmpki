package com.fxal.km.protocol.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author caiming
 * @title: KeyRequest
 * @projectName IBK-KMC
 * @description: TODO
 * @date 2019/7/23 002309:23
 */
public class CARequest extends ASN1Object {

    private KSRequest ksRequest;
    private AlgorithmIdentifier signatureAlgorithm;
    private ASN1OctetString signatureValue;

    public static CARequest getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CARequest getInstance(Object obj) {
        if (obj instanceof CARequest) {
            return (CARequest) obj;
        }
        if (obj != null) {
            return new CARequest(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    protected CARequest(ASN1Sequence seq) {
        ksRequest = KSRequest.getInstance(seq.getObjectAt(0));
        signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        signatureValue = ASN1OctetString.getInstance(seq.getObjectAt(2));
    }

    public CARequest(KSRequest ksRequest, AlgorithmIdentifier signatureAlgorithm, ASN1OctetString signatureValue) {
        this.ksRequest = ksRequest;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureValue = signatureValue;
    }

    public CARequest(KSRequest ksRequest) {
        this.ksRequest = ksRequest;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(ksRequest);
        seq.add(signatureAlgorithm);
        seq.add(signatureValue);
        return new DERSequence(seq);
    }


    public KSRequest getKsRequest() {
        return ksRequest;
    }

    public ASN1OctetString getSignatureValue() {
        return signatureValue;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
