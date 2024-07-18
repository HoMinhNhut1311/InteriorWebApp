package com.hominhnhut.WMN_BackEnd.domain.request;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IntrospectRequest {

    String token;
}
