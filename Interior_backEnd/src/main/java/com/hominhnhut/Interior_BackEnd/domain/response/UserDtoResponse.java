package com.hominhnhut.WMN_BackEnd.domain.response;

import com.hominhnhut.WMN_BackEnd.domain.enity.MediaFile;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserDtoResponse {

    String userId;

    String profileId;

    String userName;

//    String password;

    String fullName;

    boolean sex;

    String email;

    String phone;

    LocalDate birth;

    Set<String> roleNames;

    MediaFile mediaFile;

}
