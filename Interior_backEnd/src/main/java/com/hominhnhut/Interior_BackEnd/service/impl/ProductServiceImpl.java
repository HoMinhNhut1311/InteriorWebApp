package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Category;
import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import com.hominhnhut.WMN_BackEnd.domain.request.ProductRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.impl.ProductMapper;
import com.hominhnhut.WMN_BackEnd.repository.CategoryRepository;
import com.hominhnhut.WMN_BackEnd.repository.ProductRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.ProductService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Slf4j
public class ProductServiceImpl implements ProductService {

    ProductRepository productRepository;
    CategoryRepository categoryRepository;
    ProductMapper productMapper;


    @Override
    public ProductResponse saveProduct(ProductRequest productRequest) {
        Category category = categoryRepository.findById(productRequest.getCategoryId())
                .orElseThrow(() -> new AppException(errorType.CategoryIdIsNotExist));

        Product existingProduct = productRepository.getProductByProductName(productRequest.getProductName());
        if (existingProduct != null) {
            throw new AppException(errorType.ProductNameIsExist);
        }

        Product product = productMapper.mapFromRequest(productRequest);
        product.setCategory(category);
        Product savedProduct = productRepository.save(product);

        return productMapper.mapToResponese(savedProduct);
    }


    @Override
    public void deleteProduct(String productId) {
        Product product = productRepository.findById(productId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        productRepository.deleteById(productId);
    }

    @Override
    public ProductResponse updateProduct(String productId, ProductRequest productRequest) {
        Product product = productRepository.findById(productId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );

        Product productUpdate = productMapper.mapFromRequest(productRequest);
        productUpdate.setCategory(product.getCategory());
        productUpdate.setImage(product.getImage());
        productUpdate.setProductId(productId);
        return productMapper.mapToResponese(productRepository.save(productUpdate));
    }

    @Override
    public Set<ProductResponse> findAll() {
        List<ProductResponse> responses = productRepository.findAll().stream().map(productMapper::mapToResponese).toList();
        return new HashSet<>(responses);
    }

    @Override
    public ProductResponse findProductById(String productId) {
        Product product = productRepository.findById(productId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        return productMapper.mapToResponese(product);
    }

    @Override
    public Set<ProductResponse> getProductByProductNameContaining(String productName) {
        Pageable pageable = PageRequest.of(0, 5);
        return new HashSet<>(
                this.productRepository.findAllByProductNameContaining(productName, pageable).stream()
                        .map(this.productMapper::mapToResponese).toList()
        );
    }

    @Override
    public ProductResponse getProductBestSeller() {
        Product product = productRepository.getProductBestSeller();
        return productMapper.mapToResponese(product);
    }


}
