
package com.fxal.ca.protocol.cmp.enums;

/**
 *  @author: caiming
 *  @Date: 2022/5/16 16:30
 *  @Description:
 */ 


public enum ProtectionResult {

  SIGNATURE_VALID,
  SIGNATURE_INVALID,
  SIGNATURE_ALGO_FORBIDDEN,
  MAC_VALID,
  MAC_INVALID,
  MAC_ALGO_FORBIDDEN,
  SENDER_NOT_AUTHORIZED

}
