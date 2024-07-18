package com.hominhnhut.WMN_BackEnd.restController;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.hominhnhut.WMN_BackEnd.domain.request.*;
import com.hominhnhut.WMN_BackEnd.domain.response.AuthenticationResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.AuthService;
import com.hominhnhut.WMN_BackEnd.service.Interface.MailService;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserService;
import com.nimbusds.jose.JOSEException;
import jakarta.mail.MessagingException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;

@CrossOrigin(origins = "http://localhost:5173/")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@RestController
public class AuthController {

    AuthService authService;
    UserService userService;
    MailService mailService;


    @GetMapping("/auth/google/url")
    public ResponseEntity<String> getGoogleAuthorizationUrl() {
        String url  = authService.getUserToUrlOauth2();
        return ResponseEntity.ok(url);
    }

        @GetMapping("/auth/google/callback")
    public ResponseEntity<AuthenticationResponse> callback(
            @RequestParam("code") String code
    ) throws IOException {
        AuthenticationResponse response = authService.LoginGoogle(code);
        return ResponseEntity.ok(response);
    }



    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> Login(
            @RequestBody AuthenticationRequest request
    ) {
        AuthenticationResponse response = authService.Login(request);
        return ResponseEntity.ok(response);
    }
    @PostMapping("/register")
    public ResponseEntity<UserDtoResponse> Register(
            @RequestBody RegisterRequest registerRequest
    ) throws MessagingException {
        MailRequest request = new MailRequest(registerRequest.getEmail(),"Mật khẩu của bạn","acdb");
        mailService.send(request);
        UserDtoResponse response = authService.register(registerRequest);
        if (response == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(null);
        }
        return ResponseEntity.ok(response);
    }
    @PostMapping("/introspect")
    public ResponseEntity<Boolean> Introspect(
           @RequestBody IntrospectRequest request) throws ParseException, JOSEException {
        boolean isValid = authService.Introspect(request);
        return ResponseEntity.ok(isValid);
    }

    @PostMapping("/resetPassword")
    public ResponseEntity<UserDtoResponse> changeMyPass(
            @AuthenticationPrincipal Jwt jwt, @RequestBody ChangePasswordRequest changePasswordRequest
    ) {
        UserDtoResponse response = userService.resetPassword(jwt.getClaimAsString("sub"),
                changePasswordRequest.getPwNew());
        return ResponseEntity.ok(response);
    }
}