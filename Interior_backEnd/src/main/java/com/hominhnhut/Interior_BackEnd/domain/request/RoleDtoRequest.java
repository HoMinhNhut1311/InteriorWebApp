package com.hominhnhut.WMN_BackEnd.domain.request;


import jakarta.validation.constraints.NotBlank;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
public class RoleDtoRequest {


    @NotBlank
    String roleName;

    @NotBlank
    String description;

}
