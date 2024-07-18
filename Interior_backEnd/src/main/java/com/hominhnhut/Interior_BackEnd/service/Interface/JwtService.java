package com.hominhnhut.WMN_BackEnd.service.Interface;

import org.springframework.stereotype.Component;

@Component
public interface JwtService {

    String extractUsername(String token);

    String extractPassword(String password);

}
