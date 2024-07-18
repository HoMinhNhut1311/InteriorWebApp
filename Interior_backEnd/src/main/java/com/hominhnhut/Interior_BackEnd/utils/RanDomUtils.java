package com.hominhnhut.WMN_BackEnd.utils;

import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.RandomCode;
import com.hominhnhut.WMN_BackEnd.domain.response.VerifyEmailResponse;
import com.hominhnhut.WMN_BackEnd.repository.UserProfileRepository;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RanDomUtils {

    final UserProfileRepository userProfileRepository;
    final jwtUtils jwtUtils;

    @Getter
    private final ArrayList<RandomCode> randomCodes = new ArrayList<>();

    public String getRandomString(String email) {
        String random = generateRandomNumber(6);

        // Kiểm tra và cập nhật RandomCode nếu email đã tồn tại trong randomCodes
        boolean isEmailExist = false;
        for (RandomCode randomCode : randomCodes) {
            if (randomCode.getEmail().equals(email)) {
                System.out.println(randomCode.getEmail());
                isEmailExist = true;
                randomCode.setDate(Date.from(Instant.now().plus(60, ChronoUnit.SECONDS)));
                randomCode.setRandomCode(random);
                break;
            }
        }

        randomCodes.forEach((rdc) -> {
            System.out.println(rdc.getEmail() + " - "+rdc.getRandomCode() + " - "+rdc.getDate());
        });

        // Nếu email chưa tồn tại, tạo mới RandomCode và thêm vào randomCodes
        if (!isEmailExist) {
            RandomCode randomCode = RandomCode.builder()
                    .email(email)
                    .date(Date.from(Instant.now().plus(60, ChronoUnit.SECONDS))) // Thời gian hết hạn là 180 giây (3 phút)
                    .randomCode(random)
                    .build();
            randomCodes.add(randomCode);
        }

        return random;
    }

    public VerifyEmailResponse verifyRandomCode(String email, String randomCode) {
        for (RandomCode rdC : randomCodes) {
            if (rdC.getRandomCode().equals(randomCode) && rdC.getEmail().equals(email)
                    && rdC.getDate().after(new Date())) { // Kiểm tra xem RandomCode còn hiệu lực
                UserProfile userProfile = userProfileRepository.getUserProfileByProfileEmail(rdC.getEmail()).orElseThrow();
                User user = userProfile.getUser();
                String token = jwtUtils.generateToken(user);
                return VerifyEmailResponse.builder()
                        .isValid(true)
                        .token(token)
                        .build();
            }
        }
        return VerifyEmailResponse.builder()
                .isValid(false)
                .build();
    }

    public void deleteRandomCode(RandomCode randomCode) {
        randomCodes.remove(randomCode);
    }

    public String generateRandomNumber(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(random.nextInt(10)); // Chọn một chữ số ngẫu nhiên từ 0 đến 9
        }
        return sb.toString();
    }
}
