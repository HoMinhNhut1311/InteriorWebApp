package com.hominhnhut.WMN_BackEnd.domain.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ProductResponse {

    private String productName;
    private String productId;
    private double productPrice;
    private String productDes;
    private int stock;
    private String categoryName;
    private String mediaFilePath;


}
