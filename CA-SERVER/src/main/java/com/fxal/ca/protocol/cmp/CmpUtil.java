
package com.fxal.ca.protocol.cmp;

import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.signer.SignerUtil;
import com.fxal.ca.util.EdECConstants;
import com.fxal.ca.util.KeyUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static com.fxal.ca.util.Args.notNull;

/**
 * @author: caiming
 * @Date: 2022/5/9 10:38
 * @Description:
 */
@Slf4j
public class CmpUtil {

    private CmpUtil() {
    }

    public static PKIMessage addProtection(PKIMessage pkiMessage, ContentSigner signer,
                                           GeneralName signerName, boolean addSignerCert, X509Certificate signerCert) throws CertificateEncodingException, IOException, CMPException {
        notNull(pkiMessage, "pkiMessage");
        notNull(signer, "signer");
        ProtectedPKIMessageBuilder builder =
                newProtectedPKIMessageBuilder(pkiMessage, signerName, null);
        if (addSignerCert) {
            builder.addCMPCertificate(new X509CertificateHolder(signerCert.getEncoded()));
        }

        ProtectedPKIMessage signedMessage;
        signedMessage = builder.build(signer);
        return signedMessage.toASN1Structure();
    } // method addProtection

    public static PKIMessage addProtection(PKIMessage pkiMessage, char[] password,
                                           PBMParameter pbmParameter, GeneralName signerName, byte[] senderKid)
            throws CMPException {
        ProtectedPKIMessageBuilder builder =
                newProtectedPKIMessageBuilder(pkiMessage, signerName, senderKid);
        ProtectedPKIMessage signedMessage;
        try {
            PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());
            pkMacBuilder.setParameters(pbmParameter);
            signedMessage = builder.build(pkMacBuilder.build(password));
        } catch (CRMFException ex) {
            throw new CMPException(ex.getMessage(), ex);
        }
        return signedMessage.toASN1Structure();
    } // method addProtection

    // CHECKSTYLE:SKIP
    private static ProtectedPKIMessageBuilder newProtectedPKIMessageBuilder(PKIMessage pkiMessage,
                                                                            GeneralName sender, byte[] senderKid) {
        PKIHeader header = pkiMessage.getHeader();
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                sender, header.getRecipient());
        PKIFreeText freeText = header.getFreeText();
        if (freeText != null) {
            builder.setFreeText(freeText);
        }

        InfoTypeAndValue[] generalInfo = header.getGeneralInfo();
        if (generalInfo != null) {
            for (InfoTypeAndValue gi : generalInfo) {
                builder.addGeneralInfo(gi);
            }
        }

        ASN1OctetString octet = header.getRecipKID();
        if (octet != null) {
            builder.setRecipKID(octet.getOctets());
        }

        octet = header.getRecipNonce();
        if (octet != null) {
            builder.setRecipNonce(octet.getOctets());
        }

        if (senderKid != null) {
            builder.setSenderKID(senderKid);
        }

        octet = header.getSenderNonce();
        if (octet != null) {
            builder.setSenderNonce(octet.getOctets());
        }

        octet = header.getTransactionID();
        if (octet != null) {
            builder.setTransactionID(octet.getOctets());
        }

        if (header.getMessageTime() != null) {
            builder.setMessageTime(new Date());
        }
        builder.setBody(pkiMessage.getBody());

        return builder;
    } // method newProtectedPKIMessageBuilder

    public static boolean isImplictConfirm(PKIHeader header) {
        notNull(header, "header");

        InfoTypeAndValue[] regInfos = header.getGeneralInfo();
        if (regInfos != null) {
            for (InfoTypeAndValue regInfo : regInfos) {
                if (CMPObjectIdentifiers.it_implicitConfirm.equals(regInfo.getInfoType())) {
                    return true;
                }
            }
        }

        return false;
    } // method isImplictConfirm

    public static InfoTypeAndValue getImplictConfirmGeneralInfo() {
        return new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE);
    }

    public static CmpUtf8Pairs extractUtf8Pairs(InfoTypeAndValue[] generalInfo) {
        if (generalInfo != null) {
            for (InfoTypeAndValue itv : generalInfo) {
                if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(itv.getInfoType())) {
                    String regInfoValue = ((ASN1String) itv.getInfoValue()).getString();
                    return new CmpUtf8Pairs(regInfoValue);
                }
            }
        }

        return null;
    }

    public static CmpUtf8Pairs extractUtf8Pairs(AttributeTypeAndValue[] atvs) {
        if (atvs != null) {
            for (AttributeTypeAndValue atv : atvs) {
                if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(atv.getType())) {
                    String regInfoValue = ((ASN1String) atv.getValue()).getString();
                    return new CmpUtf8Pairs(regInfoValue);
                }
            }
        }

        return null;
    }

    public static InfoTypeAndValue buildInfoTypeAndValue(CmpUtf8Pairs utf8Pairs) {
        notNull(utf8Pairs, "utf8Pairs");
        return new InfoTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String(utf8Pairs.encoded()));
    }

    public static AttributeTypeAndValue buildAttributeTypeAndValue(CmpUtf8Pairs utf8Pairs) {
        notNull(utf8Pairs, "utf8Pairs");
        return new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String(utf8Pairs.encoded()));
    }

    public static void addErrCertResp(List<CertResponse> resps, ASN1Integer certReqId,
                                      int pkiFailureInfo, String pkiStatusText) {
        resps.add(new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText)));
    }

    public static CertResponse addErrCertResp(ASN1Integer certReqId,
                                      int pkiFailureInfo, String pkiStatusText){
        return new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText));
    }

    public static PKIStatusInfo generateRejectionStatus(Integer info, String errorMessage) {
        return generateRejectionStatus(PKIStatus.rejection, info, errorMessage);
    } // method generateCmpRejectionStatus

    public static PKIStatusInfo generateRejectionStatus(PKIStatus status, Integer info,
                                                        String errorMessage) {
        PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
        PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
        return new PKIStatusInfo(status, statusMessage, failureInfo);
    } // method generateCmpRejectionStatus

    public static boolean verifyPopo(CertificateRequestMessage certRequest, SubjectPublicKeyInfo spki,
                              boolean allowRaPopo) {
        int popType = certRequest.getProofOfPossessionType();
        if (popType == CertificateRequestMessage.popRaVerified && allowRaPopo) {
            return true;
        }

        if (popType != CertificateRequestMessage.popSigningKey) {
            log.error("unsupported POP type: " + popType);
            return false;
        }

        // check the POP signature algorithm
        ProofOfPossession pop = certRequest.toASN1Structure().getPopo();
        POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());
        if (!popoSign.getAlgorithmIdentifier().getAlgorithm().equals(GMObjectIdentifiers.sm2_with_sm3)) {
            log.error("Cannot parse POPO signature algorithm");
            return false;
        }

        try {
            PublicKey publicKey = KeyUtil.generatePublicKey(spki);

            ContentVerifierProvider cvp = SignerUtil.getGMContentVerifierProvider(publicKey);
            return certRequest.isValidSigningKeyPOP(cvp);
        } catch (InvalidKeySpecException | IllegalStateException | CRMFException | InvalidKeyException ex) {
            ex.printStackTrace();
            log.error(ex.getLocalizedMessage());
        }
        return false;
    } // method verifyPopo
}
