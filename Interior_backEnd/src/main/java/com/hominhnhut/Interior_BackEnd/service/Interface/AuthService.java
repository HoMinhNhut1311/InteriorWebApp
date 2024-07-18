package com.hominhnhut.WMN_BackEnd.service.Interface;


import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.request.AuthenticationRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.IntrospectRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.RegisterRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.UserGoogleInfo;
import com.hominhnhut.WMN_BackEnd.domain.response.AuthenticationResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.nimbusds.jose.JOSEException;

import java.io.IOException;
import java.text.ParseException;

public interface AuthService {

    AuthenticationResponse Login(AuthenticationRequest request);

    String getUserToUrlOauth2();

    AuthenticationResponse LoginGoogle(String code) throws IOException;

    boolean Introspect(IntrospectRequest request) throws ParseException, JOSEException;
    UserDtoResponse register(RegisterRequest registerRequest);

}