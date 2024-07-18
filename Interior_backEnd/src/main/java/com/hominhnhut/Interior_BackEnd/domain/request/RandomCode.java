package com.hominhnhut.WMN_BackEnd.domain.request;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.util.Date;

@Getter
@Setter
@Builder
public class RandomCode {

    private String email;
    private String randomCode;
    private Date date;
}
