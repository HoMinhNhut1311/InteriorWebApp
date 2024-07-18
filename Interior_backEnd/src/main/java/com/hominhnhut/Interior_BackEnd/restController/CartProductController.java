package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.enity.CartProduct;
import com.hominhnhut.WMN_BackEnd.domain.response.RevenueResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.CartProductService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.Set;

@RestController
@RequestMapping("/cartProduct")
public class CartProductController {

    private final CartProductService cartProductService;

    public CartProductController(CartProductService cartProductService) {
        this.cartProductService = cartProductService;
    }

    @GetMapping("/statistical")
    public ResponseEntity<Set<RevenueResponse>> StatisticalByLocalDate(
            @RequestParam LocalDate localDate
    ) {
        Set<RevenueResponse> cartProducts = cartProductService.StatisticalByLocalDate(localDate);
        return ResponseEntity.ok(cartProducts);
    }
}