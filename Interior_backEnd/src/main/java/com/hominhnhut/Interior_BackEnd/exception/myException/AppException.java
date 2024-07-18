package com.hominhnhut.WMN_BackEnd.exception.myException;

import com.hominhnhut.WMN_BackEnd.exception.errorType;

public class AppException extends RuntimeException{

    private errorType errorType;

    public AppException(errorType errorType) {
        this.errorType = errorType;
    }

    public errorType getErrorType() {
        return errorType;
    }

    public void setErrorType(errorType errorType) {
        this.errorType = errorType;
    }
}
