package com.hominhnhut.WMN_BackEnd.domain.request;


import com.hominhnhut.WMN_BackEnd.validator.BirthConstraint;
import jakarta.persistence.Lob;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserProfileDtoRequest {

    @NotBlank
    String fullname;

    @NotNull
    boolean sex;

    @BirthConstraint(min = 5, message = "Số tuổi phải lớn hơn 5")
    LocalDate birth;

    @NotBlank
    String email;

    @NotBlank
    String phone;

    @NotBlank
    String userId;

}
