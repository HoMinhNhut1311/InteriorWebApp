package com.hominhnhut.WMN_BackEnd.mapper.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.MediaFile;
import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import com.hominhnhut.WMN_BackEnd.domain.request.ProductRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import com.hominhnhut.WMN_BackEnd.repository.MediaFileRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class ProductMapper implements
        MyMapperInterFace<ProductRequest, Product, ProductResponse> {

    ModelMapper modelMapper;
    MediaFileRepository mediaFileRepository;

    @Override
    public Product mapFromRequest(ProductRequest R) {
        return modelMapper.map(R, Product.class);
    }

    @Override
    public ProductResponse mapToResponese(Product product) {
        ProductResponse response = modelMapper.map(product, ProductResponse.class);
        if (product.getImage() != null) {
            response.setMediaFilePath(product.getImage().getMediaFilePath());
        }
        return response;
    }

    @Override
    public Product mapNewProvider(Product product, Product eUpdate) {
        return null;
    }
}
