package com.hominhnhut.WMN_BackEnd.exception;

import com.hominhnhut.WMN_BackEnd.domain.response.ApiResponse;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.sql.SQLException;

@ControllerAdvice
public class SqlException {

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponse<errorType>> handle_DuplicateException(
            SQLException exception
    ) {
        ApiResponse<errorType> response = new ApiResponse<>();
        response.setMessage(exception.getMessage());
        response.setCode(Integer.parseInt(exception.getSQLState()));

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
