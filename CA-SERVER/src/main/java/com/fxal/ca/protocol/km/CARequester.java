package com.fxal.ca.protocol.km;

import com.fxal.ca.cert.FileSNAllocator;
import com.fxal.ca.cert.SM2CertUtil;
import com.fxal.ca.cert.SM2X509CertMaker;
import com.fxal.ca.common.exception.CASecurityException;
import com.fxal.ca.common.pojo.ApplyKeyResult;
import com.fxal.ca.mgmt.service.CAMgmtService;
import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.km.asn1.*;
import com.fxal.ca.server.NettyMsgCache;
import com.fxal.ca.server.km.KMClient;
import com.fxal.ca.util.*;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;


/**
 * @author: caiming
 * @Date: 2021/8/10 15:14
 * @Description:
 */
@Component
@Slf4j
public class CARequester {


    @Autowired
    private CAMgmtService caMgmtService;

    @Autowired
    private ApplyKeyRequester applyKeyRequest;

    @Autowired
    private KMClient kmClient;


@Autowired
    private NettyMsgCache<ApplyKeyResult> nettyMsgCache;

    public CertifiedKeyPair processCARequest(final CertRequest certRequest) throws Exception {
        log.info("向KM发送密钥申请请求");
        CertTemplate certTemplate = certRequest.getCertTemplate();
        Long taskNo = new Random().nextLong();
        FileSNAllocator allocator = new FileSNAllocator();
        BigInteger sn = allocator.nextSerialNumber();
        ASN1Integer userCertNo = new ASN1Integer(sn);
        SubjectPublicKeyInfo userPubKey = certTemplate.getPublicKey();
        long notBefore = certTemplate.getValidity().getNotBefore() == null ? System.currentTimeMillis() : certTemplate.getValidity().getNotBefore().getDate().getTime();
        long notAfter = certTemplate.getValidity().getNotAfter() == null ? System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000 : certTemplate.getValidity().getNotAfter().getDate().getTime();

        AppUserInfo appUserInfo = new AppUserInfo(userCertNo,userPubKey,new ASN1GeneralizedTime(new Date(notBefore)),new ASN1GeneralizedTime(new Date(notAfter)));
        ApplyKeyRequestBuilder applyKeyRequestBuilder = new ApplyKeyRequestBuilder(appUserInfo);
        ApplyKeyRequest applyKeyRequest = applyKeyRequestBuilder.build();
        KSRequestBuilder ksRequestBuilder = new KSRequestBuilder(caMgmtService.getCAEntName());
        Request request = new Request(Request.TYPE_APPLY_KEY_REQ,applyKeyRequest);
        List<Request> requests = new ArrayList<>();
        requests.add(request);
        ksRequestBuilder.setRequestList(requests);
        ksRequestBuilder.setTaskNO(taskNo);
        KSRequest ksRequest = ksRequestBuilder.build();
        CARequestBuilder caRequestBuilder = new CARequestBuilder(ksRequest);
        caRequestBuilder.setCAPrivateKey(caMgmtService.getCAPrivateKeyParameters());
        CARequest caRequest = caRequestBuilder.build();
        Channel channel = kmClient.getChannel();
        nettyMsgCache.initReceiveMsg(taskNo);
        ChannelFuture future = channel.writeAndFlush(caRequest);
        future.addListener((ChannelFutureListener) future1 -> kmClient.releaseChannel(channel));
        KeyUsage keyUsage = KeyUsage.fromExtensions(certTemplate.getExtensions());
        X500Name subject = certTemplate.getSubject();
        ApplyKeyResult applyKeyResult = nettyMsgCache.waitReceiveMsg(taskNo);
        log.info("接收KM服务响应的加密密钥对，将公钥封装为加密证书");
        PublicKey encPublicKey = KeyUtil.generatePublicKey(applyKeyResult.getPublicKeyInfo());
        SM2X509CertMaker sm2X509CertMaker = new SM2X509CertMaker(caMgmtService.getCaKeyPair(), caMgmtService.getIssuer());
        X509Certificate x509Certificate = sm2X509CertMaker.makeCertificate(userCertNo.getValue(),notBefore, notAfter, keyUsage, subject, encPublicKey);
        CertOrEncCert certOrEncCert = new CertOrEncCert(CMPCertificate.getInstance(x509Certificate.getEncoded()));
        EncryptedKey privateKey = EncryptedKey.getInstance(applyKeyResult.getEncryptedValue());
        CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert,privateKey,null);
        return certifiedKeyPair;
    }

    public void executeCARequest(){
        try {
            //生成用户的签名密钥对，公钥上传用来保护加密私钥下发
            KeyPair keyPair = SM2Util.generateKeyPair();
            ECPrivateKeyParameters priKeyParam = BCECUtil.convertPrivateKeyToParameters((BCECPrivateKey)keyPair.getPrivate());
            ECPublicKeyParameters pubKeyParam = BCECUtil.convertPublicKeyToParameters((BCECPublicKey)keyPair.getPublic());
            byte[] derPriKey = BCECUtil.convertECPrivateKeyToSEC1(priKeyParam, pubKeyParam);
            FileUtil.writeFile("target/test.xx.pri", derPriKey);

            FileSNAllocator allocator = new FileSNAllocator();
            BigInteger sn = allocator.nextSerialNumber();
            ASN1Integer userCertNo = new ASN1Integer(sn);
            //AlgorithmIdentifier algId = new AlgorithmIdentifier(GMObjectIdentifiers.ecc_pub_key);
            SubjectPublicKeyInfo userPubKey = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(new Date());
            ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(new Date());
            AppUserInfo appUserInfo = new AppUserInfo(userCertNo,userPubKey,notBefore,notAfter);
            ApplyKeyRequestBuilder applyKeyRequestBuilder = new ApplyKeyRequestBuilder(appUserInfo);
            ApplyKeyRequest applyKeyRequest = applyKeyRequestBuilder.build();
            KSRequestBuilder ksRequestBuilder = new KSRequestBuilder(caMgmtService.getCAEntName());
            Request request = new Request(Request.TYPE_APPLY_KEY_REQ,applyKeyRequest);
            List<Request> requests = new ArrayList<>();
            requests.add(request);
            ksRequestBuilder.setRequestList(requests);
            ksRequestBuilder.setTaskNO(1L);
            KSRequest ksRequest = ksRequestBuilder.build();
            CARequestBuilder caRequestBuilder = new CARequestBuilder(ksRequest);
            caRequestBuilder.setCAPrivateKey(caMgmtService.getCAPrivateKeyParameters());
            CARequest caRequest = caRequestBuilder.build();
            Channel channel = kmClient.getChannel();
            ChannelFuture future = channel.writeAndFlush(caRequest);
            future.addListener((ChannelFutureListener) future1 -> kmClient.releaseChannel(channel));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public ApplyKeyResult executeKMRespond(KMRespond kmRespond) throws CASecurityException {
        try {
            KSRespond ksRespond = kmRespond.getKsRespond();
            EntName kmName = ksRespond.getKMName();
            X509Certificate kmCert = caMgmtService.getKMX509Cert(kmName.getEntName().toString());
            if (kmCert == null) {
                throw new CASecurityException("未找到KM的证书！");
            }
            if (kmCert.getSerialNumber().compareTo(kmName.getSerialNumber().getValue()) != 0) {
                throw new CASecurityException("KM证书序列号不匹配：" + kmCert.getSerialNumber() + "/" + kmName.getSerialNumber().getValue());
            }
            if (!kmName.getHashAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm_3)) {
                throw new CASecurityException("不支持的公钥hash算法：" + kmName.getHashAlgorithm());
            }
            boolean checkCAPukHash = SM3Util.verify(kmCert.getPublicKey().getEncoded(), kmName.getEntPubKeyHash().getOctets());
            if (!checkCAPukHash) {
                throw new CASecurityException("KM公钥HASH验证失败：" + kmName.getEntName());
            }

            if (!kmRespond.getSignatureAlgorithm().getAlgorithm().equals(GMObjectIdentifiers.sm2_with_sm3)) {
                throw new CASecurityException("不支持的签名算法：" + kmRespond.getSignatureAlgorithm().getAlgorithm().toString());
            }


            BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(kmCert);
            byte[] hashData = SM3Util.hash(ksRespond.getEncoded());
            boolean ksRequestVerifySign = SM2Util.verify(pubKey, hashData, kmRespond.getSignatureValue().getOctets());
            if (!ksRequestVerifySign) {
                throw new CASecurityException("KM密钥请求验签失败：" + kmName.getEntName());
            }

            if (ksRespond.getVersion().getValue().compareTo(new BigInteger("1")) != 0) {
                throw new CASecurityException("KM响应版本错误：" + ksRespond.getVersion().getValue());
            }

            for(Respond respond :ksRespond.getRespondList()){
                switch (respond.getType()){
                    case 0:
                        RetKeyRespond retKeyRespond = RetKeyRespond.getInstance(respond.getContent());
                        ApplyKeyResult applyKeyResult = applyKeyRequest.executeRetKeyRespond(retKeyRespond);
                        return applyKeyResult;
                    case 1:
                        return null;
                }
            }
        }catch (Exception e){
            e.printStackTrace();
            if (e instanceof CASecurityException) {
                throw new CASecurityException(e.getLocalizedMessage());
            } else {
                throw new CASecurityException("未知的系统错误：" + e.getLocalizedMessage());
            }
        }
        return null;

    }

}
