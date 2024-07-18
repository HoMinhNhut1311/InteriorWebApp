package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.request.ProductRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.PageService;
import com.hominhnhut.WMN_BackEnd.service.Interface.ProductService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.Set;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/product")
@Slf4j
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class ProductController {

    ProductService productService;
    PageService pageService;

    @GetMapping
    public ResponseEntity<
            Set<ProductResponse>> findAllProduct() {
        Set<ProductResponse> responses = productService.findAll();
        return ResponseEntity.ok(responses);
    }
    @GetMapping("/bestSeller")
    public ResponseEntity<ProductResponse> getProductBestSeller() {
        ProductResponse response = productService.getProductBestSeller();
        return ResponseEntity.ok(response);
    }
    @GetMapping("/{id}")
    public ResponseEntity<ProductResponse> findProductById(
            @PathVariable("id") String productId
    )  {
        ProductResponse response = productService.findProductById(productId);
        return ResponseEntity.ok(response);
    }

    @PostMapping
    public ResponseEntity<ProductResponse> saveProduct(
            @RequestBody ProductRequest request
            ) {
        ProductResponse response = productService.saveProduct(request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProduct(
            @PathVariable("id") String productId
    ) {
        productService.deleteProduct(productId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}")
    public ResponseEntity<ProductResponse> updateProduct(
            @PathVariable("id") String productId,
            @RequestBody ProductRequest productRequest
    ) {
        ProductResponse response = productService.updateProduct(productId,productRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/page")
    public ResponseEntity<
            Page<ProductResponse>> getPageProductByCategoryId(
            @RequestParam("categoryId") String categoryId,
            @RequestParam("pageNumber") Integer pageNumber,
            @RequestParam("pageSize") Integer pageSize
    ) {
        Page<ProductResponse> responses = pageService.
                getPageProductByCategoryId(pageNumber,pageSize,categoryId);
        return ResponseEntity.ok(responses);
    }

    @GetMapping("/productName/{productName}")
    public ResponseEntity<
            Set<ProductResponse>> getPageProductByProductNameContaining(
                    @PathVariable("productName") String productName
    )  {
        Set<ProductResponse> responses = productService.getProductByProductNameContaining(productName);
        return ResponseEntity.ok(responses);
    }



}
