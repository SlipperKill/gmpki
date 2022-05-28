package com.fxal.ca.common.exception;

/**
 *  @author: caiming
 *  @Date: 2021/7/28 15:31
 *  @Description:
 */ 

public class InvalidX500NameException extends Exception {
    private static final long serialVersionUID = 3192247087539921768L;

    public InvalidX500NameException() {
        super();
    }

    public InvalidX500NameException(String message) {
        super(message);
    }

    public InvalidX500NameException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidX500NameException(Throwable cause) {
        super(cause);
    }
}
