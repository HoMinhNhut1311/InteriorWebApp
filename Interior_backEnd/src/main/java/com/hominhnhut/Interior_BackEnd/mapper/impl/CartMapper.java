package com.hominhnhut.WMN_BackEnd.mapper.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Cart;
import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import com.hominhnhut.WMN_BackEnd.domain.request.CartRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class CartMapper implements
        MyMapperInterFace<CartRequest, Cart, CartResponse> {
    private final ModelMapper modelMapper;

    @Override
    public Cart mapFromRequest(CartRequest R) {
        Cart cart = modelMapper.map(R, Cart.class);
        return cart;
    }

    @Override
    public CartResponse mapToResponese(Cart cart) {
        CartResponse response = modelMapper.map(cart, CartResponse.class);
        response.setUsername(cart.getUser().getUsername());
//       response.setProduct();
        return response;
    }

    @Override
    public Cart mapNewProvider(Cart cart, Cart eUpdate) {
        return null;
    }
}
