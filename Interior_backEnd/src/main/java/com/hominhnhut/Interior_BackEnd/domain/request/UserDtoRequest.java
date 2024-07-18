package com.hominhnhut.WMN_BackEnd.domain.request;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
public class UserDtoRequest {

    @NotEmpty(message = "khong duoc de trong")
    String username;

    @NotBlank
    String password;

    @NotEmpty
    Set<String> roleNames;

}
