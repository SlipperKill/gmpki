
package com.fxal.ca.mgmt;

/**
 *  @author: caiming
 *  @Date: 2022/5/10 9:20
 *  @Description:
 */

public class CaMgmtException extends Exception {

  public CaMgmtException() {
  }

  public CaMgmtException(String message, Throwable cause) {
    super(message, cause);
  }

  public CaMgmtException(String message) {
    super(message);
  }

  public CaMgmtException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
