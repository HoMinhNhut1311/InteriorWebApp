package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.CartProduct;
import com.hominhnhut.WMN_BackEnd.domain.response.RevenueResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.Set;

public interface CartProductRepository extends JpaRepository<CartProduct, Long> {

    @Query("SELECT new com.hominhnhut.WMN_BackEnd.domain.response.RevenueResponse(p.productName, SUM(p.productPrice * cp.quantity)) " +
            "FROM CartProduct cp " +
            "JOIN cp.product p " +
            "JOIN cp.cart c " +
            "WHERE c.localDate = :localDate " +
            "GROUP BY p.productName")
    Set<RevenueResponse> getProductSoldByLocalDate(@Param("localDate") LocalDate localDate);
}