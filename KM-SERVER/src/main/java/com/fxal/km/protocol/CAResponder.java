package com.fxal.km.protocol;

import com.fxal.km.common.exception.KMSecurityException;
import com.fxal.km.common.util.SM2CertUtil;
import com.fxal.km.common.util.SM2Util;
import com.fxal.km.common.util.SM3Util;
import com.fxal.km.mgmt.service.KMMgmtService;
import com.fxal.km.protocol.asn1.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
@Slf4j
public class CAResponder {

    @Autowired
    private KMMgmtService kmMgmtService;

    @Autowired
    private ApplyKeyResponder applyKeyResponder;

    public KMRespond execute(CARequest caRequest) throws KMSecurityException {
        try {
            KSRequest ksRequest = caRequest.getKsRequest();
            EntName caName = ksRequest.getCaName();
            X509Certificate caCert = kmMgmtService.getCAX509Cert(caName.getEntName().toString());
            if (caCert == null) {
                throw new KMSecurityException("未找到该CA的证书！");
            }
            if (caCert.getSerialNumber().compareTo(caName.getSerialNumber().getValue()) !=0 ) {
                throw new KMSecurityException("CA证书序列号不匹配：" + caCert.getSerialNumber() + "/" + caName.getSerialNumber().getValue());
            }
            if (!caName.getHashAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm_3)) {
                throw new KMSecurityException("不支持的公钥hash算法：" + caName.getHashAlgorithm());
            }
            boolean checkCAPukHash = SM3Util.verify(caCert.getPublicKey().getEncoded(), caName.getEntPubKeyHash().getOctets());
            if (!checkCAPukHash) {
                throw new KMSecurityException("CA公钥HASH验证失败：" + caName.getEntName());
            }

            if (!caRequest.getSignatureAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm2_with_sm3)) {
                throw new KMSecurityException("不支持的签名算法：" + caRequest.getSignatureAlgorithm().getAlgorithm().toString());
            }

            BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(caCert);
            byte[] hashData = SM3Util.hash(ksRequest.getEncoded());
            boolean ksRequestVerifySign = SM2Util.verify(pubKey, hashData, caRequest.getSignatureValue().getOctets());
            if(!ksRequestVerifySign){
                throw new KMSecurityException("CA密钥请求验签失败："+caName.getEntName());
            }

            if(ksRequest.getVersion().getValue().compareTo(new BigInteger("1"))!=0){
                throw new KMSecurityException("CA密钥请求版本错误："+ksRequest.getVersion().getValue());
            }

            ASN1EncodableVector responds = new ASN1EncodableVector();
            for(Request request :ksRequest.getRequestList()){
                switch (request.getType()){
                    case 0:
                        ApplyKeyRequest applyKeyRequest = ApplyKeyRequest.getInstance(request.getContent());
                        RetKeyRespond retKeyRespond = applyKeyResponder.execute(applyKeyRequest,caName);
                        Respond respond = new Respond(Respond.TYPE_APPLY_KEY_REP,retKeyRespond);
                        responds.add(respond);
                        break;
                    case 1:
                        break;
                }
            }

            EntName KMName = kmMgmtService.getKMEntName();
            ASN1Sequence respondList = new DERSequence(responds);
            ASN1GeneralizedTime respondTime = new ASN1GeneralizedTime(new Date());
            ASN1Integer taskNO = ksRequest.getTaskNO();
            KSRespond ksRespond = new KSRespond(KMName,respondList,respondTime,taskNO);

            KMRespond kmRespond = signKMRespond(ksRespond);
            return kmRespond;

        } catch (Exception e) {
            e.printStackTrace();
            if (e instanceof KMSecurityException) {
                throw new KMSecurityException(e.getLocalizedMessage());
            } else {
                throw new KMSecurityException("未知的系统错误：" + e.getLocalizedMessage());
            }
        }
    }

    private KMRespond signKMRespond(final KSRespond ksRespond) throws KMSecurityException {
        try {
            byte[] hashData = SM3Util.hash(ksRespond.getEncoded());
            byte[] sign = SM2Util.sign(kmMgmtService.getKMPrivateKey(), hashData);
            AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm2_with_sm3);
            ASN1OctetString signatureValue = new DEROctetString(sign);
            KMRespond kmRespond = new KMRespond(ksRespond,signatureAlgorithm,signatureValue);
            return kmRespond;
        }catch (Exception e){
            e.printStackTrace();
            throw new KMSecurityException("KMRespond签名错误：" + e.getLocalizedMessage());
        }
    }

}
