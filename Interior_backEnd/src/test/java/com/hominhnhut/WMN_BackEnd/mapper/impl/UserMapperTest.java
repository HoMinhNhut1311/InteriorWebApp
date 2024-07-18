//package com.hominhnhut.WMN_BackEnd.mapper.impl;
//
//import com.hominhnhut.WMN_BackEnd.domain.enity.User;
//import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
//import com.hominhnhut.WMN_BackEnd.domain.request.UserDtoRequest;
//import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.modelmapper.ModelMapper;
//
//import java.time.LocalDate;
//import java.util.Date;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//class UserMapperTest {
//
//    private ModelMapper modelMapper;
//    private UserMapper userMapper;
//
//    @BeforeEach
//    public void setup() {
//        this.modelMapper = new ModelMapper();
//        this.userMapper = new UserMapper(modelMapper);
//    }
//
//    @Test
//    public void testMapToRequest() {
//        UserDtoRequest request = new UserDtoRequest();
//        request.setUsername("minh nhut");
//        request.setPassword("1");
//
//        User user = userMapper.mapFromRequest(request);
//
//        assertEquals(user.getUsername(),request.getUsername());
//        assertEquals(user.getPassword(),request.getPassword());
//    }
//
//    @Test
//    public void testMapToResponse() {
//        UserProfile userProfile = new UserProfile();
//        userProfile.setProfileFullName("Hồ Minh Nhựt");
//        userProfile.setProfileBirth(LocalDate.now());
//        userProfile.setProfileEmail("hnhut1200@gmail.com");
//        userProfile.setProfileSex(true);
//        userProfile.setProfileId("myId");
//        userProfile.setProfilePhone("1234567");
//
//        User user = new User();
//        user.setUserProfile(userProfile);
//        user.setUsername("minh nhut");
//        user.setPassword("1");
//
//        UserDtoResponse response = this.userMapper.mapToResponese(user);
//        System.out.println(response.getFullName());
//
//        assertEquals(response.getUserName(),user.getUsername());
//        assertEquals(response.getEmail(),user.getUserProfile().getProfileEmail());
//        assertEquals(response.getPhone(),user.getUserProfile().getProfilePhone());
//        assertEquals(response.getFullName(),user.getUserProfile().getProfileFullName());
//        assertEquals(response.isSex(),user.getUserProfile().isProfileSex());
//    }
//
//    @Test
//    public void testMapFromProvider() {
//        User user = new User();
//        user.setUsername("minh nhut");
//        user.setPassword("1");
//
//        UserProfile userProfile = new UserProfile();
//        userProfile.setProfileId("profile Id");
//        userProfile.setProfileFullName("Hồ Minh Nhựt");
//        userProfile.setProfileBirth(LocalDate.now());
//        userProfile.setProfileEmail("hnhut1200@gmail.com");
//        userProfile.setProfileSex(true);
//        userProfile.setProfileId("myId");
//        userProfile.setProfilePhone("1234567");
//        user.setUserProfile(userProfile);
//
//        User userUpdate = new User();
//        userUpdate.setUsername("update");
//        userUpdate.setPassword("pass update");
//
//        UserProfile userProfileUpdate = new UserProfile();
//        userProfileUpdate.setProfileId("update Profile Id");
//        userProfileUpdate.setProfileFullName("Hồ Minh Nhựt -Update");
//        userProfileUpdate.setProfileBirth(LocalDate.now());
//        userProfileUpdate.setProfileEmail("hnhut1200@gmail.com - Update");
//        userProfileUpdate.setProfileSex(false);
//        userProfileUpdate.setProfileId("myId -Update");
//        userProfileUpdate.setProfilePhone("1234567 - Update");
//        userUpdate.setUserProfile(userProfileUpdate);
//
//        User userNew = this.userMapper.mapNewProvider(user,userUpdate);
//
//        System.out.println(user.getUserProfile().getProfilePhone());
//
//        assertEquals(userUpdate.getUsername(),userNew.getUsername());
//        assertEquals(userUpdate.getPassword(),userNew.getPassword());
//
//        assertEquals(userUpdate.getUserProfile().getProfileEmail(),userNew.getUserProfile().getProfileEmail());
//        assertEquals(user.getUserProfile().getProfilePhone(),userNew.getUserProfile().getProfilePhone());
//        assertEquals(userUpdate.getUserProfile().getProfileId(),userNew.getUserProfile().getProfileId());
//
//    }
//
//
//
//}