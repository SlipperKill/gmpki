package com.fxal.km.common.exception;

/**
 * @author: caiming
 * @Date: 2021/7/30 15:51
 * @Description:
 */
public class KMSecurityException extends Exception{

    private static final long serialVersionUID = 1L;

    private String code;

    public KMSecurityException() {
        super();
    }

    public KMSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public KMSecurityException(String code, String message) {
        super(message);
        this.code = code;
    }

    public KMSecurityException(String message) {
        super(message);
    }

    public KMSecurityException(Throwable cause) {
        super(cause);
    }

    public String getCode() {
        return code;
    }
}
