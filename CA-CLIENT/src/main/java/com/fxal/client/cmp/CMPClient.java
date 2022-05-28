package com.fxal.client.cmp;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.collection.CollectionUtil;
import com.fxal.client.cmp.signer.GMContentSignerBuilder;
import com.fxal.client.cmp.signer.SignerUtil;
import com.fxal.client.constants.DNObjectIdentifier;
import com.fxal.client.constants.GMObjectIdentifiers;
import com.fxal.client.constants.ProtectionResult;
import com.fxal.client.netty.CAClient;
import com.fxal.client.util.*;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.*;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: caiming
 * @Date: 2022/5/17 10:08
 * @Description:
 */
@Component
@Slf4j
public class CMPClient {

    private final int PVNO_CMP2000 = 2;

    //测试用密钥对
    private KeyPair testKeyPair;

    //作消息的临时存储
    public ConcurrentHashMap<String, PKIMessage> msgMap = new ConcurrentHashMap();

    private Map<Integer, String> reqIdIdMap = new HashMap<>();

    @Autowired
    private CAClient client;

    //测试加密数据
    public final byte[] SRC_DATA_24B = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};


    /**
     * @author: caiming
     * @Date: 2022/5/18 10:39
     * @Description: 证书主题，如名称，地址，组织机构等基本信息
     */

    public X500Name getTestSubject() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        //随便设置几个。。
        x500NameBuilder.addRDN(DNObjectIdentifier.CN, "test");
        x500NameBuilder.addRDN(DNObjectIdentifier.OU, "greatwall");
        X500Name subject = x500NameBuilder.build();
        log.info("生成测试用证书主题"+subject);
        return subject;
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:39
     * @Description: 签名公钥
     */

    public SubjectPublicKeyInfo getTestSignPublicKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        log.info("生成测试用签名公钥(加密私钥保护公钥)");
        if (testKeyPair == null) {
            testKeyPair = SM2Util.generateKeyPair();
        }
        SubjectPublicKeyInfo userPubKey = SubjectPublicKeyInfo.getInstance(testKeyPair.getPublic().getEncoded());
        return userPubKey;
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:39
     * @Description: 证书有效期
     */

    public OptionalValidity getCertValidityTime() {
        log.info("生成证书有效期");
        Time notBefore = new Time(new Date());
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 1);
        Time notAfter = new Time(calendar.getTime());
        OptionalValidity certValidity = new OptionalValidity(notBefore, notAfter);
        return certValidity;
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:44
     * @Description: 证书中的密钥用途（签名）
     */
    public KeyUsage getSignKeyUsage() {
        log.info("生成证书密钥用途（签名）");
        int keyUsage = KeyUsage.digitalSignature;
        return new KeyUsage(keyUsage);
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:44
     * @Description: 证书中的密钥用途（加密）
     */
    public KeyUsage getEncKeyUsage() {
        log.info("生成证书密钥用途（加密、密钥交换）");
        int keyUsage = KeyUsage.dataEncipherment | KeyUsage.keyAgreement | KeyUsage.keyEncipherment;
        return new KeyUsage(keyUsage);
    }

    public ExtendedKeyUsage getExtendedKeyUsage() {
        log.info("生成证书扩展密钥用途");
        return new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
    }


    public ProofOfPossession buildPopo(CertRequest certReq) throws InvalidKeyException {
        log.info("build POP");
        GMContentSignerBuilder gmContentSignerBuilder = new GMContentSignerBuilder();
        ProofOfPossessionSigningKeyBuilder popoBuild = new ProofOfPossessionSigningKeyBuilder(certReq);
        POPOSigningKey popoSigningKey = popoBuild.build(gmContentSignerBuilder.build(testKeyPair.getPrivate()));
        return new ProofOfPossession(popoSigningKey);
    }

    public X509Certificate getClientCert() throws CertificateException, IOException, NoSuchProviderException {
        log.info("从管理系统或数据库中获得证书申请客户端(如：RA)的证书");
        //将“test.user.cer”证书当做测试客户端的证书
        X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.user.cer");
        return cert;
    }

    public PrivateKey getClientPri() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        log.info("获得证书申请客户端(如：RA)的私钥");
        //将“test.user.pri”证书当做测试客户端的私钥
        byte[] privateKeyData = FileUtil.readFile("src/main/resources/certs/test.user.pri");
        PrivateKey privateKey = BCECUtil.convertSEC1ToBCECPrivateKey(privateKeyData);
        return privateKey;
    }


    public X500Name getClientX500Name() throws CertificateException, IOException, NoSuchProviderException {
        return X500Name.getInstance(getClientCert().getSubjectX500Principal().getEncoded());
    }

    public X509Certificate getCACert() throws CertificateException, IOException, NoSuchProviderException {
        log.info("从管理系统或数据库中获得CA系统的证书");
        //CA的证书，和CA服务端的证书一致
        X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.root.ca.cer");
        return cert;
    }

    public X500Name getCAX500Name() throws CertificateException, IOException, NoSuchProviderException {
        //CA的证书，和CA服务端的证书一致
        X509Certificate cert = getCACert();
        return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    }

    public PKIBody buildReqBody(List<CertReqMsg> certReqMsgList) {
        //可以发送多个证书申请，这里测试只发送一个申请
        CertReqMessages certReqMessages = new CertReqMessages(certReqMsgList.toArray(new CertReqMsg[0]));
        PKIBody reqBody = new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages);
        return reqBody;
    }

    private X500Name getX500Sender(PKIHeader reqHeader) {
        GeneralName requestSender = reqHeader.getSender();
        if (requestSender.getTagNo() != GeneralName.directoryName) {
            return null;
        }
        return (X500Name) requestSender.getName();
    } // method getX500Sender

    public PKIMessage addProtection(PKIMessage pkiMessage) throws InvalidKeyException, CertificateException, IOException, NoSuchProviderException, CMPException, NoSuchAlgorithmException, InvalidKeySpecException {
        log.info("增加 请求PKIMessage protection");
        GMContentSignerBuilder contentSignerBuilder = new GMContentSignerBuilder();
        return CmpUtil.addProtection(pkiMessage, contentSignerBuilder.build(getClientPri()), new GeneralName(getClientX500Name()), true, getClientCert());
    } // method addProtection

    private ProtectionResult verifyProtection(GeneralPKIMessage pkiMessage, X509Certificate cert) throws CMPException, InvalidKeyException, CertificateException, IOException, NoSuchProviderException {
        log.info("验证CA响应PKIMessage protection");
        ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

        PKIHeader header = protectedMsg.getHeader();
        X500Name sender = getX500Sender(header);
        if (sender == null) {
            return ProtectionResult.SENDER_NOT_AUTHORIZED;
        }

        AlgorithmIdentifier protectionAlg = header.getProtectionAlg();
        if (!protectionAlg.getAlgorithm().equals(GMObjectIdentifiers.sm2_with_sm3)) {
            return ProtectionResult.SIGNATURE_ALGO_FORBIDDEN;
        }

        if (!sender.equals(getCAX500Name())) {
            return ProtectionResult.SENDER_NOT_AUTHORIZED;
        }

        ContentVerifierProvider verifierProvider = SignerUtil.getGMContentVerifierProvider(cert.getPublicKey());
        if (verifierProvider == null) {
            return ProtectionResult.SENDER_NOT_AUTHORIZED;
        }

        boolean signatureValid = protectedMsg.verify(verifierProvider);
        return signatureValid ? ProtectionResult.SIGNATURE_VALID : ProtectionResult.SIGNATURE_INVALID;
    } // method verifyProtection

    public void processRespPKIMessage(final PKIMessage respPKIMessage, Channel channel) throws Exception {
        GeneralPKIMessage response = new GeneralPKIMessage(respPKIMessage);
        PKIHeader respHeader = respPKIMessage.getHeader();
        PKIBody respBody = respPKIMessage.getBody();
        String tidStr = Base64.encode(respHeader.getTransactionID().getEncoded());
        PKIMessage reqPKIMessage = msgMap.get(tidStr);
        PKIHeader reqHeader = reqPKIMessage.getHeader();
        ASN1OctetString tid = reqHeader.getTransactionID();
        ASN1OctetString respTid = respHeader.getTransactionID();
        if (!tid.equals(respTid)) {
            throw new CmpClientException("请求与响应消息中的事务ID不一致");
        }
        ASN1OctetString senderNonce = reqHeader.getSenderNonce();
        ASN1OctetString respRecipientNonce = respHeader.getRecipNonce();

        if (!senderNonce.equals(respRecipientNonce)) {
            throw new CmpClientException("请求与响应消息中的临时随机数不一致");
        }
        GeneralName rec = respHeader.getRecipient();
        if (!reqHeader.getSender().equals(rec)) {
            throw new CmpClientException("不能识别的消息响应者");
        }

        if (response.hasProtection()) {
            try {
                ProtectionResult result = verifyProtection(response, getCACert());
                boolean valid = result == ProtectionResult.MAC_VALID
                        || result == ProtectionResult.SIGNATURE_VALID;
                if (!valid) {
                    throw new PKIErrorException(-1,
                            PKIFailureInfo.badMessageCheck, "验证响应消息签名失败");
                }
            } catch (InvalidKeyException | CMPException | CertificateException | NoSuchProviderException ex) {
                throw new CmpClientException(ex.getMessage(), ex);
            }
        } else {
            int bodyType = respBody.getType();
            if (bodyType != PKIBody.TYPE_ERROR) {
                throw new CmpClientException("响应消息没有签名");
            }
        }

        final int bodyType = respBody.getType();

        switch (bodyType) {
            case PKIBody.TYPE_ERROR:
                log.info("CA响应：PKIBody.TYPE_ERROR");
                ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
                throw new PKIErrorException(content.getPKIStatusInfo());
            case PKIBody.TYPE_INIT_REP:
                log.info("CA响应：PKIBody.TYPE_INIT_REP");
                boolean needCertConfirm = false;
                if (!CmpUtil.isImplictConfirm(respHeader)) {
                    needCertConfirm = true;
                }
                CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
                CertificateConfirmationContent certConfirm = processCertRepMessage(certRep, needCertConfirm);
                PKIMessage confirmPKIMessage = buildCertConfirmRequest(tid, certConfirm);
                log.info("证书与加密密钥对确认无误，向CA发送证书确认消息");
                channel.writeAndFlush(confirmPKIMessage);
                msgMap.remove(tidStr);
                break;
            case PKIBody.TYPE_CERT_REP:
                break;
            default:
                throw new CmpClientException("不能识别的消息类型 " + bodyType);

        }

    }

    private byte[] randomSenderNonce() {
        byte[] bytes = new byte[16];
        new Random().nextBytes(bytes);
        return bytes;
    }

    private byte[] randomTransactionId() {
        byte[] tid = new byte[20];
        new Random().nextBytes(tid);
        return tid;
    }


    private PKIHeader buildPkiHeader(boolean addImplictConfirm, ASN1OctetString tid, InfoTypeAndValue... additionalGeneralInfos) throws CertificateException, IOException, NoSuchProviderException {
        if (additionalGeneralInfos != null) {
            for (InfoTypeAndValue itv : additionalGeneralInfos) {
                if (itv == null) {
                    continue;
                }

                ASN1ObjectIdentifier type = itv.getInfoType();
                if (CMPObjectIdentifiers.it_implicitConfirm.equals(type)) {
                    throw new IllegalArgumentException(
                            "additionGeneralInfos contains not-permitted ITV implicitConfirm");
                }

                if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(type)) {
                    throw new IllegalArgumentException(
                            "additionGeneralInfos contains not-permitted ITV utf8Pairs");
                }
            }
        }

        PKIHeaderBuilder hdrBuilder =
                new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(getClientX500Name()), new GeneralName(getCAX500Name()));
        hdrBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        ASN1OctetString tmpTid = (tid == null) ? new DEROctetString(randomTransactionId()) : tid;
        hdrBuilder.setTransactionID(tmpTid);

        hdrBuilder.setSenderNonce(randomSenderNonce());

        List<InfoTypeAndValue> itvs = new ArrayList<>(2);
        if (addImplictConfirm) {
            itvs.add(CmpUtil.getImplictConfirmGeneralInfo());
        }

        if (additionalGeneralInfos != null) {
            for (InfoTypeAndValue itv : additionalGeneralInfos) {
                if (itv != null) {
                    itvs.add(itv);
                }
            }
        }

        if (CollectionUtil.isNotEmpty(itvs)) {
            hdrBuilder.setGeneralInfo(itvs.toArray(new InfoTypeAndValue[0]));
        }

        return hdrBuilder.build();
    } // method buildPkiHeader

    private PKIMessage buildCertConfirmRequest(ASN1OctetString tid,
                                               CertificateConfirmationContent certConfirm)
            throws CertificateException, IOException, NoSuchProviderException {
        PKIHeader header = buildPkiHeader(true, tid, null, null);
        PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
        return new PKIMessage(header, body);
    } // method buildCertConfirmRequest

    public CertificateConfirmationContent processCertRepMessage(CertRepMessage certRepMsg, boolean needCertConfirm) throws Exception {
        CertResponse[] certResponses = certRepMsg.getResponse();
        CertificateConfirmationContentBuilder certConfirmBuilder = null;
        if (needCertConfirm) {
            certConfirmBuilder = new CertificateConfirmationContentBuilder();
        }
        for (CertResponse certRep : certResponses) {
            BigInteger certReqId = certRep.getCertReqId().getValue();
            String thisId = reqIdIdMap.get(certReqId.intValue());
            if (thisId != null) {
                reqIdIdMap.remove(certReqId);
            } else if (reqIdIdMap.size() == 1) {
                thisId = reqIdIdMap.values().iterator().next();
                reqIdIdMap.clear();
            }
            if (thisId == null) {
                continue; // ignore it. this cert is not requested by me
            }
            log.info("cert req :" + thisId);
            PKIStatusInfo statusInfo = certRep.getStatus();
            int status = statusInfo.getStatus().intValue();
            if (status == PKIStatus.GRANTED || status == PKIStatus.GRANTED_WITH_MODS) {
                CertifiedKeyPair cvk = certRep.getCertifiedKeyPair();
                if (cvk == null) {
                    continue;
                }

                CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
                if (cmpCert == null) {
                    continue;
                }
                System.out.println("申请到的证书：");
                X509Certificate x509Certificate = SM2CertUtil.getX509Certificate(cmpCert.getX509v3PKCert().getEncoded());
                System.out.println(x509Certificate);
                System.out.println("验证证书有效期 begin");
                x509Certificate.checkValidity();
                System.out.println("验证证书有效期 end");
                System.out.println("验证证书签名 begin");
                x509Certificate.verify(getCACert().getPublicKey());
                System.out.println("验证证书签名 end");

                EncryptedKey encryptedKey = cvk.getPrivateKey();
                if (encryptedKey != null) {
                    // decryp the encrypted private key
                    if (encryptedKey.isEncryptedValue()) {
                        EncryptedValue encryptedValue = EncryptedValue.getInstance(encryptedKey.getValue());
                        if (!GMObjectIdentifiers.sm_4.equals(encryptedValue.getSymmAlg().getAlgorithm())) {
                            throw new CmpClientException("不支持的对称加密算法：" + encryptedValue.getSymmAlg().toString());
                        }
                        if (!GMObjectIdentifiers.sm_2.equals(encryptedValue.getKeyAlg().getAlgorithm())) {
                            throw new CmpClientException("不支持的非对称加密算法：" + encryptedValue.getKeyAlg().toString());
                        }
                        byte[] secretKey = SM2Util.decrypt((BCECPrivateKey) testKeyPair.getPrivate(), SM2Util.decodeDERSM2Cipher(encryptedValue.getEncSymmKey().getOctets()));
                        byte[] privateKeyData = SM4Util.decrypt_ECB_Padding(secretKey, encryptedValue.getEncValue().getOctets());
                        PrivateKeyInfo sm2PrivateKey = PrivateKeyInfo.getInstance(privateKeyData);

                        ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters(BCECUtil.convertPKCS8ToECPrivateKey(BCECUtil.convertECPrivateKeySEC1ToPKCS8(sm2PrivateKey.getPrivateKey().getOctets())));
                        System.out.println("CA响应userPriKey：" + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
                        byte[] encryptedData = SM2Util.encrypt(BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(cmpCert.getX509v3PKCert().getSubjectPublicKeyInfo()), SRC_DATA_24B);
                        System.out.println("SM2 加密 result:\n" + ByteUtils.toHexString(encryptedData));
                        byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
                        System.out.println("SM2 解密 result:\n" + ByteUtils.toHexString(decryptedData));
                        if (!Arrays.equals(decryptedData, SRC_DATA_24B)) {
                            System.out.println("使用CA下发的密钥测试加解密失败");
                        } else {
                            System.out.println("使用CA下发的加密密钥对测试加解密成功");
                        }
                    } else {
                        EnvelopedData envelopedData = EnvelopedData.getInstance(encryptedKey.getValue());
                        //数字证书类型的结构暂未实现
                    }

                }
                if (certConfirmBuilder != null) {
                    X509CertificateHolder certHolder = new X509CertificateHolder(cmpCert.getX509v3PKCert());
                    certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
                }


                log.info("将申请的数字证书写到resources/certs/"+thisId+".cer");
                FileUtil.writeFile("src/main/resources/certs/"+thisId+".cer",x509Certificate.getEncoded());

            } else {
                throw new PKIErrorException(statusInfo);
            }
        }
        if (needCertConfirm) {
            return certConfirmBuilder.build(new SM3DigestCalculatorProvider());
        }
        return null;
    }

    public void testSendCertReq() throws Exception {
        log.info("测试申请双证书，签名证书和加密证书，加密证书需要到KM服务申请加密密钥对");
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        certTemplateBuilder.setSubject(getTestSubject());
        certTemplateBuilder.setPublicKey(getTestSignPublicKey());
        certTemplateBuilder.setValidity(getCertValidityTime());
        List<Extension> signCertextensions = new LinkedList<>();
        log.info("签名证书请求生成-----------------begin-----------------");
        signCertextensions.add(new Extension(Extension.keyUsage, false, getSignKeyUsage().getEncoded()));
        signCertextensions.add(new Extension(Extension.extendedKeyUsage, false, getExtendedKeyUsage().getEncoded()));
        certTemplateBuilder.setExtensions(new Extensions(signCertextensions.toArray(new Extension[0])));
        log.info("签名证书模板build");
        CertTemplate signCertTemplate = certTemplateBuilder.build();
        CertRequest signCertReq = new CertRequest(1, signCertTemplate, null);
        CertReqMsg signCertReqMsg = new CertReqMsg(signCertReq, buildPopo(signCertReq), null);
        reqIdIdMap.put(1, "签名证书");
        log.info("签名证书请求生成-----------------end-----------------");
        log.info("加密证书请求生成-----------------begin-----------------");
        List<Extension> encCertextensions = new LinkedList<>();
        encCertextensions.add(new Extension(Extension.keyUsage, false, getEncKeyUsage().getEncoded()));
        encCertextensions.add(new Extension(Extension.extendedKeyUsage, false, getExtendedKeyUsage().getEncoded()));
        certTemplateBuilder.setExtensions(new Extensions(encCertextensions.toArray(new Extension[0])));
        log.info("加密证书模板build");
        CertTemplate encCertTemplate = certTemplateBuilder.build();
        CertRequest encCertReq = new CertRequest(2, encCertTemplate, null);
        reqIdIdMap.put(2, "加密证书");
        CertReqMsg encCertReqMsg = new CertReqMsg(encCertReq, buildPopo(encCertReq), null);
        log.info("加密证书请求生成-----------------end-----------------");

        List<CertReqMsg> certReqMsgList = new ArrayList<>();
        certReqMsgList.add(signCertReqMsg);
        certReqMsgList.add(encCertReqMsg);

        PKIHeader reqHeader = buildPkiHeader(true, null, null);
        PKIBody reqBody = buildReqBody(certReqMsgList);
        PKIMessage reqPKIMessage = new PKIMessage(reqHeader, reqBody);
        reqPKIMessage = addProtection(reqPKIMessage);

        Channel channel = client.getChannel();
        log.info("向CA发送证书申请请求");
        ChannelFuture future = channel.writeAndFlush(reqPKIMessage);
        future.addListener((ChannelFutureListener) future1 -> client.getChannelPool().release(channel));
        String tidStr = Base64.encode(reqHeader.getTransactionID().getEncoded());
        msgMap.put(tidStr, reqPKIMessage);
    }
}
