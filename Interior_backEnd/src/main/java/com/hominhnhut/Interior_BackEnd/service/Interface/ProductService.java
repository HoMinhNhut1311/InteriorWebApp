package com.hominhnhut.WMN_BackEnd.service.Interface;

import com.hominhnhut.WMN_BackEnd.domain.request.ProductRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Set;

@Service
public interface ProductService {

    ProductResponse saveProduct(ProductRequest productRequest);
    ProductResponse getProductBestSeller();

    void deleteProduct(String productId);

    ProductResponse updateProduct(String productId, ProductRequest productRequest);

    Set<ProductResponse> findAll();

    ProductResponse findProductById(String productId);

    Set<ProductResponse> getProductByProductNameContaining(String productName);
}
