package com.hominhnhut.WMN_BackEnd.service.Interface;


import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.UserProfileDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;

import java.util.List;

public interface UserProfileService {

    List<UserDtoResponse> findAll();

    UserDtoResponse getById(String id);

    UserDtoResponse save(UserProfileDtoRequest request);

    UserDtoResponse update(String idUpdate, UserProfileDtoRequest request);

    void delete(String idDelete);

    UserProfile getUserProfileByEmail(String email);
}

