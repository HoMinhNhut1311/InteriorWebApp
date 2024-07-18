package com.hominhnhut.WMN_BackEnd.domain.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder

public class VerifyEmailResponse {

    private String token;

    private boolean isValid;
}
