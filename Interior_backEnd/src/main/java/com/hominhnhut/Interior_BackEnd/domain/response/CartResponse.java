package com.hominhnhut.WMN_BackEnd.domain.response;

import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CartResponse {
     String cartId;
     LocalDate localDate;
     boolean status;
     String username;
     List<ProductResponse> products;
}
