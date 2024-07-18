package com.hominhnhut.WMN_BackEnd.domain.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.domain.Page;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PageResponse {

    //
    Page<UserDtoResponse> PrevPage;
    Page<UserDtoResponse> PresentPage;
    Page<UserDtoResponse> NextPage;

    Integer pageCount;
}
