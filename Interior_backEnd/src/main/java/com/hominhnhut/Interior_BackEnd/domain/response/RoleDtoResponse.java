package com.hominhnhut.WMN_BackEnd.domain.response;

import lombok.*;
import lombok.experimental.FieldDefaults;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RoleDtoResponse {

   Integer roleId;
   String roleName;
   String description;
   Integer count = 0;

}
