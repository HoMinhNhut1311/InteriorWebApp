package com.hominhnhut.WMN_BackEnd.mapper.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.UserProfileDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.modelmapper.Provider;
import org.modelmapper.TypeMap;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;

@Component
@Slf4j
public class UserProfileMapper implements
        MyMapperInterFace<UserProfileDtoRequest, UserProfile, UserDtoResponse> {

    private final ModelMapper modelMapper;


    public UserProfileMapper(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;


        TypeMap<UserProfileDtoRequest, UserProfile> mapRequest =
                this.modelMapper.createTypeMap(UserProfileDtoRequest.class,UserProfile.class);
        mapRequest.addMapping(UserProfileDtoRequest::getBirth,UserProfile::setProfileBirth);
        mapRequest.addMapping(UserProfileDtoRequest::getFullname,UserProfile::setProfileFullName);
        mapRequest.addMapping(UserProfileDtoRequest::getEmail,UserProfile::setProfileEmail);
        mapRequest.addMapping(UserProfileDtoRequest::getPhone,UserProfile::setProfilePhone);


        TypeMap<UserProfile, UserDtoResponse> mapProfileToResponse =
                this.modelMapper.createTypeMap(UserProfile.class,UserDtoResponse.class);
        mapProfileToResponse.addMapping(UserProfile::getProfileBirth,UserDtoResponse::setBirth);
        mapProfileToResponse.addMapping(src -> src.getUser().getUsername()
                ,UserDtoResponse::setUserName);
        mapProfileToResponse.addMapping(UserProfile::getProfilePhone,UserDtoResponse::setPhone);
        mapProfileToResponse.addMapping(UserProfile::getProfileEmail,UserDtoResponse::setEmail);
        mapProfileToResponse.addMapping(UserProfile::getProfileFullName,UserDtoResponse::setFullName);
        mapProfileToResponse.addMapping(UserProfile::getProfileSex,UserDtoResponse::setSex);
        mapProfileToResponse.addMapping(UserProfile::getProfileId,UserDtoResponse::setProfileId);

    }

    @Override
    public UserProfile mapFromRequest(UserProfileDtoRequest R) {



        return this.modelMapper.map(R,UserProfile.class);
    }

    @Override
    public UserDtoResponse mapToResponese(UserProfile userProfile) {
        UserDtoResponse response = this.modelMapper.map(userProfile, UserDtoResponse.class);
        User user = userProfile.getUser();
        if (user != null) {
            List<String> roleName = user.getRoles().stream().map(Role::getRoleName).toList();
            response.setRoleNames(new HashSet<>(roleName));
        }

        return response;
    }

    @Override
    public UserProfile mapNewProvider(UserProfile userProfile, UserProfile eUpdate) {
        TypeMap<UserProfile, UserProfile> map =
                this.modelMapper.createTypeMap(UserProfile.class,UserProfile.class);

        Provider<UserProfile> userProfileProvider = new Provider<UserProfile>() {
            @Override
            public UserProfile get(ProvisionRequest<UserProfile> provisionRequest) {
                return userProfile;
            }
        };
        map.setProvider(userProfileProvider);

        return this.modelMapper.map(eUpdate,UserProfile.class);
    }
}
