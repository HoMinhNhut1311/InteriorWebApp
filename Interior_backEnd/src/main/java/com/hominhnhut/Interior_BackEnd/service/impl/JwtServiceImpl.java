package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.service.Interface.JwtService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService{


    @Override
    public String extractUsername(String token) {
        return null;
    }

    @Override
    public String extractPassword(String password) {
        return null;
    }
}
