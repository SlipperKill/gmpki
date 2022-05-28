
package com.fxal.client.cmp;

import org.bouncycastle.asn1.cmp.PKIStatusInfo;


public class PKIErrorException extends Exception {

  private static final long serialVersionUID = 1L;

  private final int status;

  private final int pkiFailureInfo;

  private final String statusMessage;


  public PKIErrorException(PKIStatusInfo statusInfo) {
    this(statusInfo.getStatus().intValue(), statusInfo.getFailInfo().intValue(), statusInfo.getStatusString().getStringAt(0).getString());
  }

  public PKIErrorException(int status, int pkiFailureInfo, String statusMessage) {
    this.status = status;
    this.pkiFailureInfo = pkiFailureInfo;
    this.statusMessage = statusMessage;
  }

  public PKIErrorException(int status) {
    this.status = status;
    this.pkiFailureInfo = 0;
    this.statusMessage = null;
  }

  public int getStatus() {
    return status;
  }

  public int getPkiFailureInfo() {
    return pkiFailureInfo;
  }

  public String getStatusMessage() {
    return statusMessage;
  }

  @Override
  public String toString() {
    return "PKIErrorException{" +
            "status=" + status +
            ", pkiFailureInfo=" + pkiFailureInfo +
            ", statusMessage='" + statusMessage + '\'' +
            '}';
  }
}
