package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.UserProfileDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import com.hominhnhut.WMN_BackEnd.mapper.impl.UserProfileMapper;
import com.hominhnhut.WMN_BackEnd.repository.UserProfileRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserProfileService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@FieldDefaults(makeFinal = true,level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class UserProfileServiceImpl implements UserProfileService {

    UserProfileRepository profileRepository;
    MyMapperInterFace<UserProfileDtoRequest, UserProfile, UserDtoResponse> profileMapper;



    public List<UserDtoResponse> findAll() {
        return this.profileRepository.findAll().stream()
                .map(this.profileMapper::mapToResponese).collect(Collectors.toList());
    }

    public UserDtoResponse getById(String id) {
        return this.profileRepository.findById(id).
                map(this.profileMapper::mapToResponese).orElseThrow(
                        () ->   new AppException(errorType.notFound)
                );
    }

    public UserDtoResponse save(UserProfileDtoRequest request) {
        UserProfile userProfile = this.profileMapper.mapFromRequest(request);
        User user = new User();
        user.setUserId(request.getUserId());
        userProfile.setUser(user);
        return profileMapper.
                mapToResponese(profileRepository.save(userProfile));
    }

    public UserDtoResponse update(String idUpdate,UserProfileDtoRequest request) {
            UserProfile profile = this.profileRepository.findById(idUpdate).orElseThrow(
                    () -> new AppException(errorType.notFound)
            );
            UserProfile updateProfile = this.profileMapper.mapFromRequest(request);
            updateProfile.setProfileId(idUpdate);
            updateProfile.setMediaFile(profile.getMediaFile());
            return this.profileMapper.
                mapToResponese(profileRepository.save(updateProfile));
    }

    public void delete(String idDelete) {
        UserProfile profile = this.profileRepository.findById(idDelete).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
       profileRepository.delete(profile);
    }

    @Override
    public UserProfile getUserProfileByEmail(String email) {
        return profileRepository.getUserProfileByProfileEmail(email).orElseThrow(
                () -> new AppException(errorType.EmailNotFound)
        );
    }


}
