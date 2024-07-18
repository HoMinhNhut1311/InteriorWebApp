package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.Cart;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Set;

public interface CartRepository extends JpaRepository<Cart,String> {
    @Query("Select c from Cart c " +
            "inner  join c.user u " +
            "on c.user.userId = u.userId " +
            "where u.userId = :id")
    Page<Cart> getAllByUser(@Param("id") String id, Pageable pageable);
}
