package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.response.RevenueResponse;
import com.hominhnhut.WMN_BackEnd.repository.CartProductRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.CartProductService;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Set;

@Service
public class CartProductServiceImpl implements CartProductService {

    private final CartProductRepository cartProductRepository;

    public CartProductServiceImpl(CartProductRepository cartProductRepository) {
        this.cartProductRepository = cartProductRepository;
    }

    @Override
    public Set<RevenueResponse> StatisticalByLocalDate(LocalDate localDate) {
        return cartProductRepository.getProductSoldByLocalDate(localDate);
    }
}