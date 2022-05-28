package com.fxal.ca.protocol.cmp;

import cn.hutool.core.util.HexUtil;
import com.fxal.ca.cert.CertSNAllocator;
import com.fxal.ca.cert.FileSNAllocator;
import com.fxal.ca.cert.SM2X509CertMaker;
import com.fxal.ca.mgmt.service.CAMgmtService;
import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.cmp.enums.ProtectionResult;
import com.fxal.ca.protocol.km.CARequester;
import com.fxal.ca.signer.GMContentSignerBuilder;
import com.fxal.ca.signer.SignerUtil;
import com.fxal.ca.util.Base64;
import com.fxal.ca.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;

import static com.fxal.ca.util.Args.notNull;
import static org.bouncycastle.asn1.cmp.PKIFailureInfo.badPOP;
import static org.bouncycastle.asn1.cmp.PKIStatus.GRANTED;
import static org.bouncycastle.asn1.cmp.PKIStatus.GRANTED_WITH_MODS;

/**
 * @author: caiming
 * @Date: 2022/5/13 9:00
 * @Description:
 */
@Slf4j
@Component
public class PKIMessageDispatcher {

    private static final int PVNO_CMP2000 = 2;

    private static final long MESSAGE_TIME_BIAS = 5000;

    @Autowired
    private CAMgmtService caMgmtService;

    @Autowired
    private CARequester caRequester;

    private CmpRequestor getRequestor(X500Name requestorSender) {
        CmpRequestor cmpRequestor = new CmpRequestor();
        cmpRequestor.setCert(caMgmtService.getX509Cert(requestorSender.toString()));
        cmpRequestor.setRa(caMgmtService.checkIsRa(requestorSender.toString()));
        cmpRequestor.setX500Name(requestorSender);
        return cmpRequestor;
    }

    public PKIMessage processPKIMessage(final PKIMessage reqPKIMessage) {
        notNull(reqPKIMessage, "reqPKIMessage");
        GeneralPKIMessage message = new GeneralPKIMessage(reqPKIMessage);

        PKIHeader reqHeader = reqPKIMessage.getHeader();

        X500Name x500Sender = getX500Sender(reqHeader);

        int reqPvno = reqHeader.getPvno().getValue().intValue();
        ASN1OctetString tid = reqHeader.getTransactionID();
        if (tid == null) {
            byte[] randomBytes = randomTransactionId();
            tid = new DEROctetString(randomBytes);
        }
        String tidStr = Base64.encodeToString(tid.getOctets());
        if (reqPvno < PVNO_CMP2000) {
            return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.unsupportedVersion, null);
        }
        Integer failureCode = null;
        String statusText = null;

        Date messageTime = null;
        if (reqHeader.getMessageTime() != null) {
            try {
                messageTime = reqHeader.getMessageTime().getDate();
            } catch (ParseException ex) {
                failureCode = PKIFailureInfo.badTime;
                statusText = "无法解析消息时间";
                log.error("tid=" + tidStr + ": 无法解析消息时间");
            }
        }

        GeneralName recipient = reqHeader.getRecipient();
        boolean intentMe = recipient == null || intendsMe(recipient);
        if (!intentMe) {
            log.warn("tid={}: 我不是请求希望的消息接收者, but '{}'", tid, reqHeader.getRecipient());
            failureCode = PKIFailureInfo.badRequest;
            statusText = "我不是请求希望的消息接收者";
        } else if (messageTime == null) {
            failureCode = PKIFailureInfo.missingTimeStamp;
            statusText = "缺少消息时间";
        } else {
            long msgTimeMs = messageTime.getTime();
            long currentTimeMs = System.currentTimeMillis();
            long bias = (msgTimeMs - currentTimeMs) / 1000L;
            if (bias > MESSAGE_TIME_BIAS) {
                failureCode = PKIFailureInfo.badTime;
                statusText = "message time is in the future";
            } else if (bias * -1 > MESSAGE_TIME_BIAS) {
                failureCode = PKIFailureInfo.badTime;
                statusText = "message too old";
            }
        }

        if (failureCode != null) {
            return buildErrorPkiMessage(tid, reqHeader, failureCode, statusText);
        }

        boolean isProtected = message.hasProtection();
        CmpRequestor requestor = getRequestor(x500Sender);
        String errorStatus = null;

        if (isProtected) {
            try {
                log.info("验证消息签名");
                ProtectionResult pr = verifyProtection(tidStr, message);
                if (pr == ProtectionResult.SIGNATURE_VALID || pr == ProtectionResult.MAC_VALID) {
                    errorStatus = null;
                } else if (pr == ProtectionResult.SIGNATURE_INVALID) {
                    errorStatus = "request is protected by signature but invalid";
                } else if (pr == ProtectionResult.MAC_INVALID) {
                    errorStatus = "request is protected by MAC but invalid";
                } else if (pr == ProtectionResult.SENDER_NOT_AUTHORIZED) {
                    errorStatus = "request is protected but the requestor is not authorized";
                } else if (pr == ProtectionResult.SIGNATURE_ALGO_FORBIDDEN) {
                    errorStatus = "request is protected by signature but the algorithm is forbidden";
                } else if (pr == ProtectionResult.MAC_ALGO_FORBIDDEN) {
                    errorStatus = "request is protected by MAC but the algorithm is forbidden";
                } else {
                    throw new IllegalStateException("should not reach here, unknown ProtectionResult " + pr);
                }
            } catch (Exception ex) {
                log.error("tid=" + tidStr + ": could not verify the signature");
                errorStatus = "request has invalid signature based protection";
                requestor = null;
            }
        }

        if (errorStatus != null) {
            return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.badMessageCheck, errorStatus);
        }

        PKIBody reqBody = reqPKIMessage.getBody();

        String msgId = nextHexLong();

        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(reqHeader.getPvno().getValue().intValue(), getSender(), reqHeader.getSender());
        respHeader.setTransactionID(tid);

        ASN1OctetString senderNonce = reqHeader.getSenderNonce();
        if (senderNonce != null) {
            respHeader.setRecipNonce(senderNonce);
        }

        PKIBody respBody;
        final int type = reqBody.getType();
        try {
            if (type == PKIBody.TYPE_INIT_REQ || type == PKIBody.TYPE_CERT_REQ || type == PKIBody.TYPE_KEY_UPDATE_REQ || type == PKIBody.TYPE_P10_CERT_REQ || type == PKIBody.TYPE_CROSS_CERT_REQ) {
                log.info("收到client消息类型为申请证书");
                respBody = cmpEnrollCert(reqPKIMessage, requestor);
            } else if (type == PKIBody.TYPE_CERT_CONFIRM) {
                log.info("收到client消息类型为确认证书");
                CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
                respBody = confirmCertificates(tid,certConf);
            } else {
                log.info("收到client消息类型不能识别");
                respBody = buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest, "unsupported type " + type);
            }
        } catch (Exception e) {
            e.printStackTrace();
            respBody = buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure, e.getLocalizedMessage());
        }
        if(respBody.getContent().equals(DERNull.INSTANCE)){
            return null;
        }
        PKIMessage respPKIMessage = new PKIMessage(respHeader.build(), respBody);
        if (isProtected) {
            respPKIMessage = addProtection(respPKIMessage, requestor);
        }
        return respPKIMessage;
    }

    private PKIBody cmpEnrollCert(final PKIMessage reqPKIMessage, final CmpRequestor requestor) throws Exception {
        PKIBody reqBody = reqPKIMessage.getBody();
        PKIBody respBody = null;
        int type = reqBody.getType();
        if (type == PKIBody.TYPE_INIT_REQ) {
            CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
            CertRepMessage repMessage = processCertReqMessages(cr, requestor);
            respBody = new PKIBody(PKIBody.TYPE_INIT_REP, repMessage);
        } else if (type == PKIBody.TYPE_CERT_REQ) {
            CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
            CertRepMessage repMessage = processCertReqMessages(cr, requestor);
            respBody = new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
        }
        return respBody;
    }

    private CertRepMessage processCertReqMessages(final CertReqMessages cr, final CmpRequestor requestor) throws Exception {
        CertReqMsg[] certReqMsgs = cr.toCertReqMsgArray();
        CertResponse[] resps = new CertResponse[certReqMsgs.length];
        for (int i = 0; i < certReqMsgs.length; i++) {
            CertResponse certResponse = processCertReqMessage(certReqMsgs[i], requestor);
            resps[i] = certResponse;
        }
        return new CertRepMessage(null, resps);
    }

    private CertResponse processCertReqMessage(final CertReqMsg reqMsg, final CmpRequestor requestor) throws Exception {
        CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
        CertTemplate certTemp = req.getCertTemplate();
        SubjectPublicKeyInfo publicKey = certTemp.getPublicKey();
        ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
        if (reqMsg.getPopo() == null) {
            return CmpUtil.addErrCertResp(certReqId, badPOP, "no POP");
        }
        if (!CmpUtil.verifyPopo(req, publicKey, requestor.isRa())) {
            log.warn("could not validate POP for request {}", certReqId.getValue());
            return CmpUtil.addErrCertResp(certReqId, badPOP, "invalid POP");
        }
        CertifiedKeyPair certifiedKeyPair = null;
        CertRequest certRequest = reqMsg.getCertReq();
        CertTemplate certTemplate = certRequest.getCertTemplate();
        KeyUsage keyUsage = KeyUsage.fromExtensions(certTemplate.getExtensions());
        if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
            log.info("client申请的证书密钥用途包含”dataEncipherment“,所以向KM申请加密密钥对,可根据实际策略调整");
            certifiedKeyPair = caRequester.processCARequest(certRequest);
        } else {
            log.info("client申请的证书密钥用途不包含”dataEncipherment“,直接封装数字证书,可根据实际策略调整");
            certifiedKeyPair = processCertRequest(certRequest);
        }
        PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.granted);
        return new CertResponse(certReqId, statusInfo, certifiedKeyPair, null);
    }

    private CertifiedKeyPair processCertRequest(final CertRequest certRequest) throws Exception {
        CertTemplate certTemplate = certRequest.getCertTemplate();
        SubjectPublicKeyInfo signPk = certTemplate.getPublicKey();
        PublicKey signPublicKey = KeyUtil.generatePublicKey(signPk);
        KeyUsage keyUsage = KeyUsage.fromExtensions(certTemplate.getExtensions());
        long notBefore = certTemplate.getValidity().getNotBefore() == null ? System.currentTimeMillis() : certTemplate.getValidity().getNotBefore().getDate().getTime();
        long notAfter = certTemplate.getValidity().getNotAfter() == null ? System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000 : certTemplate.getValidity().getNotAfter().getDate().getTime();
        X500Name subject = certTemplate.getSubject();
        CertSNAllocator snAllocator = new FileSNAllocator(); // 实际应用中可能需要使用数据库来维护证书序列号
        SM2X509CertMaker sm2X509CertMaker = new SM2X509CertMaker(caMgmtService.getCaKeyPair(), caMgmtService.getIssuer(), snAllocator);
        X509Certificate x509Certificate = sm2X509CertMaker.makeCertificate(notBefore, notAfter, keyUsage, subject, signPublicKey);
        CertOrEncCert certOrEncCert = new CertOrEncCert(CMPCertificate.getInstance(x509Certificate.getEncoded()));
        CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(certOrEncCert);
        return certifiedKeyPair;
    }

    public PKIMessage buildErrorPkiMessage(ASN1OctetString tid, PKIHeader requestHeader, int failureCode, String statusText) {
        log.info("buildErrorPkiMessage......");
        log.warn("tid={}:" + statusText);
        GeneralName respRecipient = requestHeader.getSender();

        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(requestHeader.getPvno().getValue().intValue(), getSender(), respRecipient);
        respHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        if (tid != null) {
            respHeader.setTransactionID(tid);
        }

        ASN1OctetString senderNonce = requestHeader.getSenderNonce();
        if (senderNonce != null) {
            respHeader.setRecipNonce(senderNonce);
        }

        PKIStatusInfo status = generateRejectionStatus(failureCode, statusText);
        ErrorMsgContent error = new ErrorMsgContent(status);
        PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, error);

        return new PKIMessage(respHeader.build(), body);
    } // method buildErrorPkiMessage

    public PKIBody confirmCertificates(ASN1OctetString transactionId,
                                       CertConfirmContent certConf) {
        log.info("confirmCertificates......");
        CertStatus[] certStatuses = certConf.toCertStatusArray();
        for (CertStatus certStatus : certStatuses) {
            PKIStatusInfo statusInfo = certStatus.getStatusInfo();
            boolean accept = true;
            if (statusInfo != null) {
                int status = statusInfo.getStatus().intValue();
                if (GRANTED != status && GRANTED_WITH_MODS != status) {
                    accept = false;
                }
            }
            if (accept) {
                log.info("client 已确认收到证书，相关证书将发布生效，transactionId="+Base64.encodeToString(transactionId.getOctets()));
                log.info("证书申请ID(reqId):" + certStatus.getCertReqId().getValue() + ",已确认的证书hash：" + Base64.encodeToString(certStatus.getCertHash().getOctets()));
            }else {
                log.info("client 已拒绝确认收到证书，相关证书将撤销，transactionId="+Base64.encodeToString(transactionId.getOctets()));
            }
        }
        return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
    }

    private PKIMessage addProtection(PKIMessage pkiMessage, CmpRequestor requestor) {
        log.info("addProtection......");
        try {
            KeyPair caKeyPair = caMgmtService.getCaKeyPair();
            GMContentSignerBuilder contentSignerBuilder = new GMContentSignerBuilder();
            if (requestor.getCert() != null) {
                return CmpUtil.addProtection(pkiMessage, contentSignerBuilder.build(caKeyPair.getPrivate()), getSender(), true, caMgmtService.getCAX509Cert());
            }

            return CmpUtil.addProtection(pkiMessage, contentSignerBuilder.build(caKeyPair.getPrivate()), getSender(), false, null);
        } catch (Exception ex) {
            log.error("could not add protection to the PKI message：" + ex.getLocalizedMessage());
            PKIStatusInfo status = generateRejectionStatus(PKIFailureInfo.systemFailure, "could not sign the PKIMessage");
            PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status));
            return new PKIMessage(pkiMessage.getHeader(), body);
        }
    } // method addProtection

    private boolean intendsMe(GeneralName requestRecipient) {
        if (requestRecipient == null) {
            return false;
        }

        if (getSender().equals(requestRecipient)) {
            return true;
        }

        if (requestRecipient.getTagNo() == GeneralName.directoryName) {
            X500Name x500Name = X500Name.getInstance(requestRecipient.getName());
//            if (x500Name.equals(caManager.getSignerWrapper(getResponderName()).getSubject())) {
//                return true;
//            }

            return x500Name.equals(X500Name.getInstance(caMgmtService.getCAX509Cert().getSubjectX500Principal().getEncoded()));
        }

        return false;
    }

    public PKIStatusInfo generateRejectionStatus(Integer info, String errorMessage) {
        return generateRejectionStatus(PKIStatus.rejection, info, errorMessage);
    } // method generateCmpRejectionStatus

    public PKIStatusInfo generateRejectionStatus(PKIStatus status, Integer info, String errorMessage) {
        PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
        PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
        return new PKIStatusInfo(status, statusMessage, failureInfo);
    } // method generateCmpRejectionStatus

    private ProtectionResult verifyProtection(String tid, GeneralPKIMessage pkiMessage) throws CMPException, InvalidKeyException {
        ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

        PKIHeader header = protectedMsg.getHeader();
        X500Name sender = getX500Sender(header);
        if (sender == null) {
            log.warn("tid={}: not authorized requestor 'null'", tid);
            return ProtectionResult.SENDER_NOT_AUTHORIZED;
        }

        AlgorithmIdentifier protectionAlg = header.getProtectionAlg();
        if (!protectionAlg.getAlgorithm().equals(GMObjectIdentifiers.sm2_with_sm3)) {
            log.warn("tid={}: not authorized protectionAlg '{}'", tid, protectionAlg.getAlgorithm().toString());
            return ProtectionResult.SIGNATURE_ALGO_FORBIDDEN;
        }

        X500Name x500Sender = getX500Sender(header);
        CmpRequestor requestor = (x500Sender == null) ? null : getRequestor(x500Sender);
        if (requestor == null) {
            log.warn("tid={}: not authorized requestor '{}'", tid, header.getSender());
            return ProtectionResult.SENDER_NOT_AUTHORIZED;
        }

        ContentVerifierProvider verifierProvider = SignerUtil.getGMContentVerifierProvider(requestor.getCert().getPublicKey());
        if (verifierProvider == null) {
            log.warn("tid={}: not authorized requestor '{}'", tid, sender);
            return ProtectionResult.SENDER_NOT_AUTHORIZED;
        }

        boolean signatureValid = protectedMsg.verify(verifierProvider);
        return signatureValid ? ProtectionResult.SIGNATURE_VALID : ProtectionResult.SIGNATURE_INVALID;
    } // method verifyProtection

    private PKIBody buildErrorMsgPkiBody(PKIStatus pkiStatus, int failureInfo, String statusMessage) {
        PKIFreeText pkiStatusMsg = (statusMessage == null) ? null : new PKIFreeText(statusMessage);
        ErrorMsgContent emc = new ErrorMsgContent(new PKIStatusInfo(pkiStatus, pkiStatusMsg, new PKIFailureInfo(failureInfo)));
        return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    private static X500Name getX500Sender(PKIHeader reqHeader) {
        GeneralName requestSender = reqHeader.getSender();
        if (requestSender.getTagNo() != GeneralName.directoryName) {
            return null;
        }

        return (X500Name) requestSender.getName();
    } // method getX500Sender

    private GeneralName getSender() {
        return caMgmtService.getCAEntName().getEntName();
    }

    private byte[] randomTransactionId() {
        byte[] bytes = new byte[10];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static String nextHexLong() {
        return Long.toHexString(new Random().nextLong());
    }
}
