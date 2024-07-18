package com.hominhnhut.WMN_BackEnd.exception;

import com.google.api.client.auth.oauth2.TokenResponseException;
import com.hominhnhut.WMN_BackEnd.domain.response.ApiResponse;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalException {


    @ExceptionHandler(AppException.class)
    public ResponseEntity<ApiResponse<errorType>> handle_AppException(
            AppException exception
    ) {
        errorType errorType = exception.getErrorType();
        ApiResponse<errorType> response = new ApiResponse<>();
        response.setMessage(errorType.getMessage());
        response.setCode(errorType.getCode());

        return ResponseEntity.status(errorType.getHttpStatus()).body(response);
    }

    @ExceptionHandler(TokenResponseException.class)
    public ResponseEntity<String> response(TokenResponseException exception) {
        String error = exception.getMessage();
        return ResponseEntity.badRequest().body(error);
    }




    // MethodArgumentTypeMismatchException
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<
            ApiResponse
            <Map<String,String>>> handle_MethodArgumentTypeMismatchException(
            MethodArgumentTypeMismatchException exception
    ) {
            Map<String ,String> canNotParse = new HashMap<>();
            String fieldName = exception.getName();
            String message = exception.getMessage();
            canNotParse.put(fieldName,message);
            ApiResponse<Map<String,String>> response = ApiResponse.<Map<String, String>>
                    builder().
                    body(canNotParse)
                    .build();
            return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<
            ApiResponse
            <Map<String,String>>> handle_MethodNotAgrumentNotValid(
            MethodArgumentNotValidException exception
    ) {
        Map<String,String> result = new HashMap<>();
         exception.getBindingResult().getAllErrors().forEach(
                (error) -> {
                    String fieldName = ((FieldError) error).getField();
                    String message= error.getDefaultMessage();
                    result.put(fieldName,message);
                }
        );
         ApiResponse<Map<String,String>> response = ApiResponse.<Map<String,String>>builder()
                 .body(result).build();
         return ResponseEntity.badRequest().body(response);
    }

}
