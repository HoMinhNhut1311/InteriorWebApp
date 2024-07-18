package com.hominhnhut.WMN_BackEnd.domain.request;


import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ProductRequest {

    private String productName;
    private String productDes;
    private double productPrice;
    private String categoryId;
    private int stock;
}
