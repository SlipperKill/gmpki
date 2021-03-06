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

    //??????????????????
    private KeyPair testKeyPair;

    //????????????????????????
    public ConcurrentHashMap<String, PKIMessage> msgMap = new ConcurrentHashMap();

    private Map<Integer, String> reqIdIdMap = new HashMap<>();

    @Autowired
    private CAClient client;

    //??????????????????
    public final byte[] SRC_DATA_24B = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};


    /**
     * @author: caiming
     * @Date: 2022/5/18 10:39
     * @Description: ???????????????????????????????????????????????????????????????
     */

    public X500Name getTestSubject() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        //????????????????????????
        x500NameBuilder.addRDN(DNObjectIdentifier.CN, "test");
        x500NameBuilder.addRDN(DNObjectIdentifier.OU, "greatwall");
        X500Name subject = x500NameBuilder.build();
        log.info("???????????????????????????"+subject);
        return subject;
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:39
     * @Description: ????????????
     */

    public SubjectPublicKeyInfo getTestSignPublicKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        log.info("???????????????????????????(????????????????????????)");
        if (testKeyPair == null) {
            testKeyPair = SM2Util.generateKeyPair();
        }
        SubjectPublicKeyInfo userPubKey = SubjectPublicKeyInfo.getInstance(testKeyPair.getPublic().getEncoded());
        return userPubKey;
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:39
     * @Description: ???????????????
     */

    public OptionalValidity getCertValidityTime() {
        log.info("?????????????????????");
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
     * @Description: ????????????????????????????????????
     */
    public KeyUsage getSignKeyUsage() {
        log.info("????????????????????????????????????");
        int keyUsage = KeyUsage.digitalSignature;
        return new KeyUsage(keyUsage);
    }

    /**
     * @author: caiming
     * @Date: 2022/5/18 10:44
     * @Description: ????????????????????????????????????
     */
    public KeyUsage getEncKeyUsage() {
        log.info("???????????????????????????????????????????????????");
        int keyUsage = KeyUsage.dataEncipherment | KeyUsage.keyAgreement | KeyUsage.keyEncipherment;
        return new KeyUsage(keyUsage);
    }

    public ExtendedKeyUsage getExtendedKeyUsage() {
        log.info("??????????????????????????????");
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
        log.info("?????????????????????????????????????????????????????????(??????RA)?????????");
        //??????test.user.cer???????????????????????????????????????
        X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.user.cer");
        return cert;
    }

    public PrivateKey getClientPri() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        log.info("???????????????????????????(??????RA)?????????");
        //??????test.user.pri???????????????????????????????????????
        byte[] privateKeyData = FileUtil.readFile("src/main/resources/certs/test.user.pri");
        PrivateKey privateKey = BCECUtil.convertSEC1ToBCECPrivateKey(privateKeyData);
        return privateKey;
    }


    public X500Name getClientX500Name() throws CertificateException, IOException, NoSuchProviderException {
        return X500Name.getInstance(getClientCert().getSubjectX500Principal().getEncoded());
    }

    public X509Certificate getCACert() throws CertificateException, IOException, NoSuchProviderException {
        log.info("????????????????????????????????????CA???????????????");
        //CA???????????????CA????????????????????????
        X509Certificate cert = SM2CertUtil.getX509Certificate("src/main/resources/certs/test.root.ca.cer");
        return cert;
    }

    public X500Name getCAX500Name() throws CertificateException, IOException, NoSuchProviderException {
        //CA???????????????CA????????????????????????
        X509Certificate cert = getCACert();
        return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    }

    public PKIBody buildReqBody(List<CertReqMsg> certReqMsgList) {
        //??????????????????????????????????????????????????????????????????
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
        log.info("?????? ??????PKIMessage protection");
        GMContentSignerBuilder contentSignerBuilder = new GMContentSignerBuilder();
        return CmpUtil.addProtection(pkiMessage, contentSignerBuilder.build(getClientPri()), new GeneralName(getClientX500Name()), true, getClientCert());
    } // method addProtection

    private ProtectionResult verifyProtection(GeneralPKIMessage pkiMessage, X509Certificate cert) throws CMPException, InvalidKeyException, CertificateException, IOException, NoSuchProviderException {
        log.info("??????CA??????PKIMessage protection");
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
            throw new CmpClientException("?????????????????????????????????ID?????????");
        }
        ASN1OctetString senderNonce = reqHeader.getSenderNonce();
        ASN1OctetString respRecipientNonce = respHeader.getRecipNonce();

        if (!senderNonce.equals(respRecipientNonce)) {
            throw new CmpClientException("???????????????????????????????????????????????????");
        }
        GeneralName rec = respHeader.getRecipient();
        if (!reqHeader.getSender().equals(rec)) {
            throw new CmpClientException("??????????????????????????????");
        }

        if (response.hasProtection()) {
            try {
                ProtectionResult result = verifyProtection(response, getCACert());
                boolean valid = result == ProtectionResult.MAC_VALID
                        || result == ProtectionResult.SIGNATURE_VALID;
                if (!valid) {
                    throw new PKIErrorException(-1,
                            PKIFailureInfo.badMessageCheck, "??????????????????????????????");
                }
            } catch (InvalidKeyException | CMPException | CertificateException | NoSuchProviderException ex) {
                throw new CmpClientException(ex.getMessage(), ex);
            }
        } else {
            int bodyType = respBody.getType();
            if (bodyType != PKIBody.TYPE_ERROR) {
                throw new CmpClientException("????????????????????????");
            }
        }

        final int bodyType = respBody.getType();

        switch (bodyType) {
            case PKIBody.TYPE_ERROR:
                log.info("CA?????????PKIBody.TYPE_ERROR");
                ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
                throw new PKIErrorException(content.getPKIStatusInfo());
            case PKIBody.TYPE_INIT_REP:
                log.info("CA?????????PKIBody.TYPE_INIT_REP");
                boolean needCertConfirm = false;
                if (!CmpUtil.isImplictConfirm(respHeader)) {
                    needCertConfirm = true;
                }
                CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
                CertificateConfirmationContent certConfirm = processCertRepMessage(certRep, needCertConfirm);
                PKIMessage confirmPKIMessage = buildCertConfirmRequest(tid, certConfirm);
                log.info("??????????????????????????????????????????CA????????????????????????");
                channel.writeAndFlush(confirmPKIMessage);
                msgMap.remove(tidStr);
                break;
            case PKIBody.TYPE_CERT_REP:
                break;
            default:
                throw new CmpClientException("??????????????????????????? " + bodyType);

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
                System.out.println("?????????????????????");
                X509Certificate x509Certificate = SM2CertUtil.getX509Certificate(cmpCert.getX509v3PKCert().getEncoded());
                System.out.println(x509Certificate);
                System.out.println("????????????????????? begin");
                x509Certificate.checkValidity();
                System.out.println("????????????????????? end");
                System.out.println("?????????????????? begin");
                x509Certificate.verify(getCACert().getPublicKey());
                System.out.println("?????????????????? end");

                EncryptedKey encryptedKey = cvk.getPrivateKey();
                if (encryptedKey != null) {
                    // decryp the encrypted private key
                    if (encryptedKey.isEncryptedValue()) {
                        EncryptedValue encryptedValue = EncryptedValue.getInstance(encryptedKey.getValue());
                        if (!GMObjectIdentifiers.sm_4.equals(encryptedValue.getSymmAlg().getAlgorithm())) {
                            throw new CmpClientException("?????????????????????????????????" + encryptedValue.getSymmAlg().toString());
                        }
                        if (!GMObjectIdentifiers.sm_2.equals(encryptedValue.getKeyAlg().getAlgorithm())) {
                            throw new CmpClientException("????????????????????????????????????" + encryptedValue.getKeyAlg().toString());
                        }
                        byte[] secretKey = SM2Util.decrypt((BCECPrivateKey) testKeyPair.getPrivate(), SM2Util.decodeDERSM2Cipher(encryptedValue.getEncSymmKey().getOctets()));
                        byte[] privateKeyData = SM4Util.decrypt_ECB_Padding(secretKey, encryptedValue.getEncValue().getOctets());
                        PrivateKeyInfo sm2PrivateKey = PrivateKeyInfo.getInstance(privateKeyData);

                        ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters(BCECUtil.convertPKCS8ToECPrivateKey(BCECUtil.convertECPrivateKeySEC1ToPKCS8(sm2PrivateKey.getPrivateKey().getOctets())));
                        System.out.println("CA??????userPriKey???" + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
                        byte[] encryptedData = SM2Util.encrypt(BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(cmpCert.getX509v3PKCert().getSubjectPublicKeyInfo()), SRC_DATA_24B);
                        System.out.println("SM2 ?????? result:\n" + ByteUtils.toHexString(encryptedData));
                        byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
                        System.out.println("SM2 ?????? result:\n" + ByteUtils.toHexString(decryptedData));
                        if (!Arrays.equals(decryptedData, SRC_DATA_24B)) {
                            System.out.println("??????CA????????????????????????????????????");
                        } else {
                            System.out.println("??????CA?????????????????????????????????????????????");
                        }
                    } else {
                        EnvelopedData envelopedData = EnvelopedData.getInstance(encryptedKey.getValue());
                        //???????????????????????????????????????
                    }

                }
                if (certConfirmBuilder != null) {
                    X509CertificateHolder certHolder = new X509CertificateHolder(cmpCert.getX509v3PKCert());
                    certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
                }


                log.info("??????????????????????????????resources/certs/"+thisId+".cer");
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
        log.info("???????????????????????????????????????????????????????????????????????????KM???????????????????????????");
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        certTemplateBuilder.setSubject(getTestSubject());
        certTemplateBuilder.setPublicKey(getTestSignPublicKey());
        certTemplateBuilder.setValidity(getCertValidityTime());
        List<Extension> signCertextensions = new LinkedList<>();
        log.info("????????????????????????-----------------begin-----------------");
        signCertextensions.add(new Extension(Extension.keyUsage, false, getSignKeyUsage().getEncoded()));
        signCertextensions.add(new Extension(Extension.extendedKeyUsage, false, getExtendedKeyUsage().getEncoded()));
        certTemplateBuilder.setExtensions(new Extensions(signCertextensions.toArray(new Extension[0])));
        log.info("??????????????????build");
        CertTemplate signCertTemplate = certTemplateBuilder.build();
        CertRequest signCertReq = new CertRequest(1, signCertTemplate, null);
        CertReqMsg signCertReqMsg = new CertReqMsg(signCertReq, buildPopo(signCertReq), null);
        reqIdIdMap.put(1, "????????????");
        log.info("????????????????????????-----------------end-----------------");
        log.info("????????????????????????-----------------begin-----------------");
        List<Extension> encCertextensions = new LinkedList<>();
        encCertextensions.add(new Extension(Extension.keyUsage, false, getEncKeyUsage().getEncoded()));
        encCertextensions.add(new Extension(Extension.extendedKeyUsage, false, getExtendedKeyUsage().getEncoded()));
        certTemplateBuilder.setExtensions(new Extensions(encCertextensions.toArray(new Extension[0])));
        log.info("??????????????????build");
        CertTemplate encCertTemplate = certTemplateBuilder.build();
        CertRequest encCertReq = new CertRequest(2, encCertTemplate, null);
        reqIdIdMap.put(2, "????????????");
        CertReqMsg encCertReqMsg = new CertReqMsg(encCertReq, buildPopo(encCertReq), null);
        log.info("????????????????????????-----------------end-----------------");

        List<CertReqMsg> certReqMsgList = new ArrayList<>();
        certReqMsgList.add(signCertReqMsg);
        certReqMsgList.add(encCertReqMsg);

        PKIHeader reqHeader = buildPkiHeader(true, null, null);
        PKIBody reqBody = buildReqBody(certReqMsgList);
        PKIMessage reqPKIMessage = new PKIMessage(reqHeader, reqBody);
        reqPKIMessage = addProtection(reqPKIMessage);

        Channel channel = client.getChannel();
        log.info("???CA????????????????????????");
        ChannelFuture future = channel.writeAndFlush(reqPKIMessage);
        future.addListener((ChannelFutureListener) future1 -> client.getChannelPool().release(channel));
        String tidStr = Base64.encode(reqHeader.getTransactionID().getEncoded());
        msgMap.put(tidStr, reqPKIMessage);
    }
}
