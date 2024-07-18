package com.hominhnhut.WMN_BackEnd.service.Interface;


import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import org.springframework.data.domain.Page;

public interface PageService {

    Page<UserDtoResponse> getPageUserByRoleId(Integer pageNumber, Integer pageSize, Integer roleId);
    Page<ProductResponse> getPageProductByCategoryId(Integer pageNumber, Integer pageSize, String categoryId);
    Page<CartResponse> getPageCartByUserId(Integer pageNumber, Integer pageSize, String userId);
    }

