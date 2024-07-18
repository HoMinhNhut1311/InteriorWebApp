package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.*;
import com.hominhnhut.WMN_BackEnd.domain.request.CartRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.ProductRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.UserDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import com.hominhnhut.WMN_BackEnd.repository.*;
import com.hominhnhut.WMN_BackEnd.service.Interface.PageService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class PageServiceImpl implements PageService {

    UserRepository userRepository;
    RoleRepository roleRepository;
    ProductRepository productRepository;
    CategoryRepository categoryRepository;
    CartRepository cartRespository;

    MyMapperInterFace<ProductRequest, Product, ProductResponse> productMapper;
    MyMapperInterFace<UserDtoRequest, User, UserDtoResponse> userMapper;
    MyMapperInterFace<CartRequest, Cart, CartResponse> cartMapper;


    // Lấy ra User theo Role
    public Page<UserDtoResponse> getPageUserByRoleId(Integer pageNumber, Integer pageSize, Integer roleId) {
        PageRequest request = PageRequest.of(pageNumber, pageSize);
        if (roleId == 0) {
            // Lấy hết
            return userRepository.findAll(request).map(userMapper::mapToResponese);
        } else {
            // Lấy Role từ Role Id
            Role role = roleRepository.findById(roleId).orElseThrow(() -> new AppException(errorType.notFound));
            return userRepository.getUsersByRoleId(roleId, request).map(userMapper::mapToResponese);
        }
    }


    public Page<ProductResponse>
    getPageProductByCategoryId(Integer pageNumber, Integer pageSize, String categoryId) {
        PageRequest request = PageRequest.of(pageNumber, pageSize);
        if (categoryId.equals("0")) {
            return productRepository.findAll(request).map(productMapper::mapToResponese);
        } else {
            Category category = categoryRepository.findById(categoryId).
                    orElseThrow(() -> new AppException(errorType.notFound));
            return productRepository.getProductByCategoryId(categoryId,request).map(productMapper::mapToResponese);
        }
    }

    @Override
    public Page<CartResponse> getPageCartByUserId(Integer pageNumber, Integer pageSize, String userId) {
        PageRequest request = PageRequest.of(pageNumber, pageSize);
        User user = userRepository.findById(userId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        return cartRespository.getAllByUser(userId, request).map(cartMapper::mapToResponese);
    }


}
