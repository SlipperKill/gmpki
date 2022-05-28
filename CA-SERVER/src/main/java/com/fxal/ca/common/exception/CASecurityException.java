package com.fxal.ca.common.exception;

/**
 * @author: caiming
 * @Date: 2021/7/28 13:41
 * @Description:
 */
public class CASecurityException extends Exception{

    private static final long serialVersionUID = 1L;

    private String code;

    public CASecurityException() {
        super();
    }

    public CASecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public CASecurityException(String code, String message) {
        super(message);
        this.code = code;
    }

    public CASecurityException(String message) {
        super(message);
    }

    public CASecurityException(Throwable cause) {
        super(cause);
    }

    public String getCode() {
        return code;
    }
}
