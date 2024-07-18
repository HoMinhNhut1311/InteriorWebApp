package com.hominhnhut.WMN_BackEnd.domain.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PaymentResponse implements Serializable {

    private String status;
    private String message;
    private String URL;
}
