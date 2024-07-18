package com.hominhnhut.WMN_BackEnd.utils;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.StringJoiner;

@Component
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Slf4j
public class jwtUtils {


    @NonFinal
    @Value("${asm.key}")
    private String SIGN_KEY;

    // Mã hóa (Encode)
    public String generateToken(User user) {
        // Header
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);

        // Claim set
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .expirationTime(
                        new Date(
          Instant.now().plus(1, ChronoUnit.DAYS).toEpochMilli()
                        )
                )
                .claim("scope",generateScope(user.getRoles()))
                .claim("userId",(user.getUserId()))
                .issueTime(new Date())
                .issuer("HoMinhNhut.com")
                .build();
        // Payload
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        // JWS Object
        JWSObject jwsObject = new JWSObject(jwsHeader,payload);

        try {
            jwsObject.sign(new MACSigner(SIGN_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Can not create Token",e);
            throw new RuntimeException(e);
        }
    }

    public boolean VerifyToken_isMatching(SignedJWT signedJWT) throws JOSEException {
        JWSVerifier jwsVerifier = new MACVerifier(SIGN_KEY.getBytes());
        return signedJWT.verify(jwsVerifier);
    }

    private String generateScope(Set<Role> roleNames) {
        StringJoiner stringJoiner = new StringJoiner(" ");
        roleNames.forEach(role -> {
            stringJoiner.add("ROLE_"+role.getRoleName());
        });
        return stringJoiner.toString();
    }

}
