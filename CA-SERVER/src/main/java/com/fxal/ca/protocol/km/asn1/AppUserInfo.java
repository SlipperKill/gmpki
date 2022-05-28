package com.fxal.ca.protocol.km.asn1;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.util.Enumeration;

/**
 * @author: caiming
 * @Date: 2021/7/28 16:40
 * @Description:
 */
public class AppUserInfo extends ASN1Object {

    private ASN1Integer userCertNo;
    private SubjectPublicKeyInfo userPubKey;
    private ASN1GeneralizedTime notBefore;
    private ASN1GeneralizedTime notAfter;
    private ASN1OctetString userName;
    private PKIFreeText dsCode;
    private PKIFreeText extendInfo;

    private AppUserInfo(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        userCertNo = ASN1Integer.getInstance(en.nextElement());
        userPubKey = SubjectPublicKeyInfo.getInstance(en.nextElement());
        notBefore = ASN1GeneralizedTime.getInstance(en.nextElement());
        notBefore = ASN1GeneralizedTime.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            switch (tObj.getTagNo()) {
                case 0:
                    userName = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 1:
                    dsCode = PKIFreeText.getInstance(tObj, true);
                    break;
                case 2:
                    extendInfo = PKIFreeText.getInstance(tObj, true);
                    break;
            }
        }
    }

    public static AppUserInfo getInstance(Object obj) {
        if (obj instanceof AppUserInfo) {
            return (AppUserInfo) obj;
        }
        if (obj != null) {
            return new AppUserInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public AppUserInfo(ASN1Integer userCertNo, SubjectPublicKeyInfo userPubKey, ASN1GeneralizedTime notBefore, ASN1GeneralizedTime notAfter, ASN1OctetString userName, PKIFreeText dsCode, PKIFreeText extendInfo) {
        this.userCertNo = userCertNo;
        this.userPubKey = userPubKey;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        if(userName!=null) {
            this.userName = userName;
        }
        if(dsCode!=null){
            this.dsCode = dsCode;
        }
        if(extendInfo!=null){
            this.extendInfo = extendInfo;
        }
    }

    public AppUserInfo(ASN1Integer userCertNo, SubjectPublicKeyInfo userPubKey, ASN1GeneralizedTime notBefore, ASN1GeneralizedTime notAfter) {
        this.userCertNo = userCertNo;
        this.userPubKey = userPubKey;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(userCertNo);
        seq.add(userPubKey);
        seq.add(notBefore);
        seq.add(notAfter);
        addOptional(seq, 0, userName);
        addOptional(seq, 1, dsCode);
        addOptional(seq, 2, extendInfo);
        return new DERSequence(seq);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(false, tagNo, obj));
        }
    }

    public ASN1Integer getUserCertNo() {
        return userCertNo;
    }

    public SubjectPublicKeyInfo getUserPubKey() {
        return userPubKey;
    }

    public ASN1GeneralizedTime getNotBefore() {
        return notBefore;
    }

    public ASN1GeneralizedTime getNotAfter() {
        return notAfter;
    }

    public ASN1OctetString getUserName() {
        return userName;
    }

    public PKIFreeText getDsCode() {
        return dsCode;
    }

    public PKIFreeText getExtendInfo() {
        return extendInfo;
    }
}
