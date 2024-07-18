package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.GmailContentRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.RandomCode;
import com.hominhnhut.WMN_BackEnd.domain.response.VerifyEmailResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.MyGmailService;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserProfileService;
import com.hominhnhut.WMN_BackEnd.utils.RanDomUtils;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@RequestMapping("/email")
public class MyGmailController {

    MyGmailService myGmailService;
    UserProfileService userProfileService;
    RanDomUtils ranDomUtils;

    @PostMapping("/sendGmail/{recipient}")
    public ResponseEntity<String> sendGmail(
            @PathVariable("recipient") String recipient,
            @RequestBody GmailContentRequest gmailContentRequest
            ) {
        myGmailService.sendEmail(recipient, gmailContentRequest.getBody()
                , gmailContentRequest.getSubject());
        return ResponseEntity.ok("Successfully");
    }

    @GetMapping("/sendGmail/forgotPassword/{recipient}")
    public ResponseEntity<String> sendGmailToResetPassword(
            @PathVariable("recipient") String recipient
    ) {
        UserProfile userProfile = userProfileService.getUserProfileByEmail(recipient);
        String random = ranDomUtils.getRandomString(recipient);
        myGmailService.sendEmail(recipient, "Mã xác nhận : "+random,
                "NH-application Đổi Mật  Khẩu");
        return ResponseEntity.ok("Successfully");
    }

    @PostMapping("/verifyCode")
    public ResponseEntity<VerifyEmailResponse> verifyCode(
            @RequestBody RandomCode randomCode
            ) {
        System.out.println(randomCode.getRandomCode());
        VerifyEmailResponse verifyRanDomCode =
                ranDomUtils.verifyRandomCode(randomCode.getEmail(),
                        randomCode.getRandomCode());
        return ResponseEntity.ok(verifyRanDomCode);
    }

}
