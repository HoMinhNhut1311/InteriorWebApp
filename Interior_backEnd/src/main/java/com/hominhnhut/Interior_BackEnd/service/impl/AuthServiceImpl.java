package com.hominhnhut.WMN_BackEnd.service.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.hominhnhut.WMN_BackEnd.domain.enity.MediaFile;
import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.AuthenticationRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.IntrospectRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.RegisterRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.UserGoogleInfo;
import com.hominhnhut.WMN_BackEnd.domain.response.AuthenticationResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.impl.UserMapper;
import com.hominhnhut.WMN_BackEnd.repository.RoleRepository;
import com.hominhnhut.WMN_BackEnd.repository.UserProfileRepository;
import com.hominhnhut.WMN_BackEnd.repository.UserRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.AuthService;
import com.hominhnhut.WMN_BackEnd.service.Interface.MyGmailService;
import com.hominhnhut.WMN_BackEnd.utils.RanDomUtils;
import com.hominhnhut.WMN_BackEnd.utils.jwtUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ExecutorService;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {
    RoleRepository roleRepository;

    UserRepository userRepository;
    UserMapper userMapper;
    PasswordEncoder passwordEncoder;
    jwtUtils jwtUtils;
    WebClient webClient;
    MyGmailService myGmailService;
    UserProfileRepository userProfileRepository;
    ExecutorService executorService;
    RanDomUtils ranDomUtils;

    @NonFinal
    @Value("${security.oauth2.resourceserver.opaquetoken.client-id}")
    String clientId;

    @NonFinal
    @Value("${security.oauth2.resourceserver.opaquetoken.client-secret}")
    String clientSecret;

    public AuthenticationResponse Login(AuthenticationRequest request) {
        User user = userRepository.findUSerByUsername(request.getUsername()).orElseThrow(
                () -> new AppException(errorType.userNameNotExist));
        UserDtoResponse userDtoResponse = userMapper.mapToResponese(user);
        boolean isMatches = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!isMatches) {
            throw new AppException(errorType.PasswordIsNotCorrect);
        }
        String token = jwtUtils.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token)
                .fullName(userDtoResponse.getFullName())
                .roleNames(userDtoResponse.getRoleNames())
                .build();
    }

    @Override
    public String getUserToUrlOauth2() {
        String url = new GoogleAuthorizationCodeRequestUrl(
                clientId,
                "http://localhost:5173/login",
                Arrays.asList("email", "profile", "openid")).build();
        return url;
    }

    @Override
    public AuthenticationResponse LoginGoogle(String code) throws IOException {

        String accessToken = new GoogleAuthorizationCodeTokenRequest(
                new NetHttpTransport(),
                new GsonFactory(),
                clientId,
                clientSecret,
                code,
                "http://localhost:5173/login").execute().getAccessToken();

        try {
            UserGoogleInfo userGoogleInfo = webClient.get()
                    .uri(uriBuilder -> uriBuilder.path("/oauth2/v3/userinfo").queryParam("access_token", accessToken)
                            .build())
                    .retrieve()
                    .bodyToMono(UserGoogleInfo.class).block();
            assert userGoogleInfo != null;
            System.out.println("Hello");
            return getUserGoogle(userGoogleInfo);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Gap loi");
            return null;
        }
    }

    private AuthenticationResponse getUserGoogle(UserGoogleInfo userGoogleInfo) {
        // Kiểm tra UserGoogleInfor có tồn tại hay chưa
        Optional<User> user = userRepository.findUsersByGoogleId(userGoogleInfo.sub());
        if (user.isPresent()) {
            // Nếu User tồn tại
            User userExist = user.get();
            String token = jwtUtils.generateToken(userExist);
            return AuthenticationResponse.builder()
                    .fullName(userExist.getUserProfile().getProfileFullName())
                    .token(token)
                    .build();
        }
        // Neu User (GoogleID) chua ton tai
        Role role = roleRepository.findRoleByRoleName("USER").orElseThrow(
                () -> new AppException(errorType.RoleNameNotFound)
        );
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        MediaFile mediaFile = MediaFile.builder()
                .mediaFileID(UUID.randomUUID().toString())
                .mediaFilePath(userGoogleInfo.picture())
                .build();
        UserProfile userProfile = UserProfile.builder()
                .profileEmail(userGoogleInfo.email())
                .profileFullName(userGoogleInfo.name())
                .mediaFile(mediaFile)
                .build();
        User userGoogle = User.builder()
                .roles(roles)
                .googleId(userGoogleInfo.sub())
                .userProfile(userProfile) // Gán userProfile đã được tạo trước đó
                .build();

        // Sau đó, cập nhật đối tượng user cho userProfile nếu cần thiết
        userProfile.setUser(userGoogle);
        userRepository.save(userGoogle);
        String token = jwtUtils.generateToken(userGoogle);
        return AuthenticationResponse.builder()
                .token(token)
                .firstOauth2(true)
                .fullName(userGoogle.getUserProfile().getProfileFullName())
                .build();
    }



    public boolean Introspect(IntrospectRequest request) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(request.getToken());
        return jwtUtils.VerifyToken_isMatching(signedJWT);
    }

    public UserDtoResponse register(RegisterRequest registerRequest) {
        System.out.println("Register request received: " + registerRequest);

        boolean usernameExists = userRepository.existsByUsername(registerRequest.getUsername());
        boolean emailExists = userProfileRepository.existsByProfileEmail(registerRequest.getEmail());

        System.out.println("Username exists: " + usernameExists);
        System.out.println("Email exists: " + emailExists);

        if (usernameExists || emailExists) {
            System.out.println("Returning null due to existing username or email");
            return null;
        } else {
            User user = new User();
            String password = passwordEncoder.encode("acdb");
            user.setPassword(password);
            user.setUsername(registerRequest.getUsername());

            UserProfile userProfile = new UserProfile();
            userProfile.setProfileEmail(registerRequest.getEmail());
            userProfile.setUser(user);
            user.setUserProfile(userProfile);

            List<Role> roleSet = registerRequest.getRoleNames().stream()
                    .map(this.roleRepository::getRoleByRoleName)
                    .toList();
            user.setRoles(new HashSet<>(roleSet));
            System.out.println("Saving user: " + user);

            User savedUser = userRepository.save(user);

            System.out.println("Saved user: " + savedUser);

            return this.userMapper.mapToResponese(savedUser);
        }
    }

}