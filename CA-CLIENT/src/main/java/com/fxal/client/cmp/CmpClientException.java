package com.fxal.client.cmp;

/**
 * @author: caiming
 * @Date: 2022/5/17 9:31
 * @Description:
 */
public class CmpClientException extends Exception{

    private static final long serialVersionUID = 1L;

    public CmpClientException() {
    }

    public CmpClientException(String message) {
        super(message);
    }

    public CmpClientException(Throwable cause) {
        super(cause);
    }

    public CmpClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
