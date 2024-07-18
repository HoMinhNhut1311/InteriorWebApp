package com.hominhnhut.WMN_BackEnd.domain.request;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthenticationRequest {

    private String username;
    private String password;
}
