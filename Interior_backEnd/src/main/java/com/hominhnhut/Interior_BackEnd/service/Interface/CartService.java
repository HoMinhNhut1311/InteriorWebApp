package com.hominhnhut.WMN_BackEnd.service.Interface;

import com.hominhnhut.WMN_BackEnd.domain.request.CartRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;

import java.util.List;

public interface CartService {
    List<CartResponse> getAllCart();
    CartResponse findCartById(String id);
    CartResponse saveCart(CartRequest cartRequest);
    CartResponse updateCart(CartRequest cartRequest,String id);
    void deleteCart(String id);

}
