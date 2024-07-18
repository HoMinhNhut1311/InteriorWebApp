package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.Set;

public interface ProductRepository extends JpaRepository<Product, String> {

    Page<Product> findAllByProductNameContaining(String usernameContain, Pageable pageable);

    Product getProductByProductId(String s);
    Product getProductByProductName(String name);
    @Query(value = "SELECT p FROM Product p " +
            "INNER JOIN p.category c ON p.category.categoryId = c.categoryId \n" +
            "WHERE c.categoryId = :categoryId")
    Page<Product> getProductByCategoryId(@Param("categoryId") String categoryId, Pageable pageable);

    @Query(value = "SELECT TOP 1 p.* FROM cart_product cp \n" +
            "            INNER JOIN cart c ON c.cart_id = cp.cart_id \n" +
            "            INNER JOIN product p ON p.product_id = cp.product_id \n" +
            "            GROUP BY p.product_id ,p.product_des,p.product_name,p.product_price,p.category_id,p.image_media_fileid,p.stock\n" +
            "            ORDER BY COUNT(cp.product_id) DESC ", nativeQuery = true)
    Product getProductBestSeller();
}
