package com.hominhnhut.WMN_BackEnd.domain.request;

public record UserGoogleInfo(
        String sub,
        String name,
        String give_name,
        String family_name,
        String picture,
        String email,
        boolean email_verified,
        String local
) {
}
