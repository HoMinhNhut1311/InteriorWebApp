package com.hominhnhut.WMN_BackEnd.mapper.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.request.UserDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.modelmapper.Provider;
import org.modelmapper.TypeMap;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;

@Component
@FieldDefaults(makeFinal = true,level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class UserMapper implements
        MyMapperInterFace<UserDtoRequest,User, UserDtoResponse> {

    ModelMapper modelMapper;
    PasswordEncoder passwordEncoder;


    @Override
    public User mapFromRequest(UserDtoRequest R) {
        User user = modelMapper.map(R,User.class);
        user.setPassword(passwordEncoder.encode(R.getPassword()));
        return user;
    }

    @Override
    public UserDtoResponse mapToResponese(User user) {

        TypeMap<User, UserDtoResponse> typeMap = modelMapper.getTypeMap(User.class,UserDtoResponse.class);
        if (typeMap == null) {
            // Respone
            TypeMap<User, UserDtoResponse> mapResponse =
                    modelMapper.createTypeMap(User.class, UserDtoResponse.class);
            mapResponse.addMapping(User::getUsername, UserDtoResponse::setUserName);
            mapResponse.addMapping(src -> src.getUserProfile().getProfileFullName(), UserDtoResponse::setFullName);
            mapResponse.addMapping(src -> src.getUserProfile().getProfileEmail(), UserDtoResponse::setEmail);
            mapResponse.addMapping(src -> src.getUserProfile().getProfileSex(), UserDtoResponse::setSex);
            mapResponse.addMapping(src -> src.getUserProfile().getProfilePhone(), UserDtoResponse::setPhone);
            mapResponse.addMapping(User::getUserId, UserDtoResponse::setUserId);
            mapResponse.addMapping(src -> src.getUserProfile().getProfileId(), UserDtoResponse::setProfileId);
            mapResponse.addMapping(src -> src.getUserProfile().getProfileBirth(), UserDtoResponse::setBirth);
            mapResponse.addMapping(src -> src.getUserProfile().getMediaFile(), UserDtoResponse::setMediaFile);
        }
        UserDtoResponse userDtoResponse = this.modelMapper.map(user,UserDtoResponse.class);
        if (user.getRoles() != null) {
            List<String> roleName = user.getRoles().stream().map(Role::getRoleName).toList();
            userDtoResponse.setRoleNames(new HashSet<>(roleName));
        }

        return userDtoResponse;

    }

    @Override
    public User mapNewProvider(User user,User userUpdate) {
        TypeMap<User,User> map =
                this.modelMapper.createTypeMap(User.class,User.class);
        Provider<User> userProvider = new Provider<User>() {
            @Override
            public User get(ProvisionRequest<User> provisionRequest) {
                return user;
            }
        };

        map.setProvider(userProvider);
        return this.modelMapper.map(userUpdate,User.class);
    }
}
