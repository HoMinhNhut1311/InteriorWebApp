package com.hominhnhut.WMN_BackEnd.service.Interface;

import com.hominhnhut.WMN_BackEnd.domain.response.RevenueResponse;

import java.time.LocalDate;
import java.util.Set;

public interface CartProductService {

    Set<RevenueResponse> StatisticalByLocalDate(LocalDate localDate);
}