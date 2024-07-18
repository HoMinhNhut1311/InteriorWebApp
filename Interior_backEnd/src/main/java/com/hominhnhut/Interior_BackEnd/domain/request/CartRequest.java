package com.hominhnhut.WMN_BackEnd.domain.request;

import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CartRequest {
    LocalDate localDate;
    boolean status;
    String username;
    List<String> productIds;

    @Override
    public String toString() {
        return "CartRequest{" +
                "localDate=" + localDate +
                ", status=" + status +
                ", username='" + username + '\'' +
                ", productIds=" + productIds +
                '}';
    }
}
