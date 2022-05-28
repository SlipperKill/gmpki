
package com.fxal.ca.common.pojo;

import com.fxal.ca.util.Args;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.util.Date;

/**
 * Certificate template data.
 *
 * @since 2.0.0
 */

public class CertTemplateData {

  private final X500Name subject;

  private final SubjectPublicKeyInfo publicKeyInfo;

  private final Date notBefore;

  private final Date notAfter;

  private final String certprofileName;

  private final boolean caGenerateKeypair;

  private final Extensions extensions;

  private final ASN1Integer certReqId;

  public CertTemplateData(X500Name subject, SubjectPublicKeyInfo publicKeyInfo, Date notBefore,
                          Date notAfter, Extensions extensions, String certprofileName) {
    this(subject, publicKeyInfo, notBefore, notAfter, extensions, certprofileName, null, false);
  }

  public CertTemplateData(X500Name subject, SubjectPublicKeyInfo publicKeyInfo,
                          Date notBefore, Date notAfter, Extensions extensions, String certprofileName,
                          ASN1Integer certReqId, boolean caGenerateKeypair) {
    this.publicKeyInfo = publicKeyInfo;
    this.subject = Args.notNull(subject, "subject");
    this.certprofileName = Args.toNonBlankLower(certprofileName, "certprofileName");
    this.extensions = extensions;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.certReqId = certReqId;
    this.caGenerateKeypair = caGenerateKeypair;
  }

  public X500Name getSubject() {
    return subject;
  }

  public SubjectPublicKeyInfo getPublicKeyInfo() {
    return publicKeyInfo;
  }

  public boolean isCaGenerateKeypair() {
    return caGenerateKeypair;
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public String getCertprofileName() {
    return certprofileName;
  }

  public Extensions getExtensions() {
    return extensions;
  }

  public ASN1Integer getCertReqId() {
    return certReqId;
  }

}
