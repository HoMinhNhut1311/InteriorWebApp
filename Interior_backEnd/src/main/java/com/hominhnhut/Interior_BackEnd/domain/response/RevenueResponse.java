package com.hominhnhut.WMN_BackEnd.domain.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RevenueResponse {
    private String productName;
    private Double revenue;
}
