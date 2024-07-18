package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import com.hominhnhut.WMN_BackEnd.domain.request.UserDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import com.hominhnhut.WMN_BackEnd.mapper.impl.UserMapper;
import com.hominhnhut.WMN_BackEnd.repository.RoleRepository;
import com.hominhnhut.WMN_BackEnd.repository.UserRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@FieldDefaults(makeFinal = true,level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    UserRepository userRepository;

    RoleRepository roleRepository;

    MyMapperInterFace<UserDtoRequest, User, UserDtoResponse> userMapper;

    PasswordEncoder passwordEncoder;

//    @PostAuthorize("hasRole('ADMIN')")
    public List<UserDtoResponse> getAll() {
        log.info("In method Get All");
        var securityContext = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Username : "+securityContext.getName());
        securityContext.getAuthorities().forEach((grand) -> {
            log.info(grand.getAuthority());
        });
        securityContext.getAuthorities().forEach((grand) -> {

        });
        return this.userRepository.findAll().stream()
              .map(this.userMapper::mapToResponese).
              collect(Collectors.toList());
    }
    public UserDtoResponse findById(String id) {
        User user = this.userRepository.findById(id).orElseThrow(()
                -> new AppException(errorType.notFound)
        );
        return this.userMapper.mapToResponese(user);
    }

    public UserDtoResponse save(UserDtoRequest request) {
        boolean existed = userRepository.existsByUsername(request.getUsername());
        if (existed) {
            throw new AppException(errorType.UsernameExisted);
        }
        User user = this.userMapper.mapFromRequest(request);
        UserProfile userProfile = new UserProfile();
        userProfile.setUser(user);

        user.setUserProfile(userProfile);
        // Thêm Role vào từ Tên RoleName
        List<Role> roleSet = request.getRoleNames().stream().map(
                this.roleRepository::getRoleByRoleName
        ).toList();
        if (roleSet.get(0) == null) {
            throw new AppException(errorType.notFoundRoleName);
        }


        user.setRoles(new HashSet<>(roleSet));

        return  this.userMapper.mapToResponese(this.userRepository.save(user));
    }


    public UserDtoResponse update(String idUpdate,UserDtoRequest userUpdate) {
        User userExist = this.userRepository.findById(idUpdate).orElseThrow(
                () -> new AppException(errorType.notFound)
        );

        List<Role> roleSet = userUpdate.getRoleNames().stream().map(
                this.roleRepository::getRoleByRoleName
        ).toList();


        User userMap = this.userMapper.mapFromRequest(userUpdate);
        userMap.setUserId(idUpdate);
        userMap.setRoles(new HashSet<>(roleSet));

        this.userRepository.saveAndFlush(userMap);
        return this.userMapper.mapToResponese(userMap);
    }

    public void delete(String idDelete) {
        User userExist = this.userRepository.findById(idDelete).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        this.userRepository.delete(userExist);
    }

    public Set<UserDtoResponse> getUserByRoleId(Integer roleId) {
        List<UserDtoResponse> responses = null;
        if (roleId == 0) {
            responses =  this.userRepository.findAll().stream().map(
                    this.userMapper::mapToResponese
            ).toList();
        }
        else {
            Role role = this.roleRepository.findById(roleId).orElseThrow(
                    () -> new AppException(errorType.notFound)
            );
            responses =  role.getUsers().stream().map(
                    this.userMapper::mapToResponese
            ).toList();
        }

        return new HashSet<>(responses);
    }

    public Set<UserDtoResponse> getUserByUsernameContaining(String usernameContain) {
        Pageable pageable = PageRequest.of(0, 7);
        return new HashSet<>(
                this.userRepository.findAllByUsernameContaining(usernameContain,pageable).stream()
                        .map(this.userMapper::mapToResponese).toList()
        );
    }

    @Override
    public UserDtoResponse getUserByUsername(String username) {
        userRepository.findUSerByUsername(username).orElseThrow(
                () -> new AppException(errorType.userNameNotExist)
        );
        return null;
    }

    @Override
    public UserDtoResponse getMyInfo() {
        var context = SecurityContextHolder.getContext().getAuthentication();
        User response = userRepository.findUSerByUsername(context.getName()).orElseThrow();
        return userMapper.mapToResponese(response);
    }

    @Override
    public UserDtoResponse changeMyPassword(String username, String pwOld, String pwNew) {
        User user = userRepository.findUSerByUsername(username).orElseThrow(
                () -> new AppException(errorType.NotFoundUsername)
        );
        boolean isPw = passwordEncoder.matches(pwOld,user.getPassword());
        if (!isPw) {
                throw new AppException(errorType.PasswordIsNotCorrect);
        }
        user.setPassword(passwordEncoder.encode(pwNew));
        log.info("Đổi mk thành công");
        return userMapper.mapToResponese(userRepository.save(user));
    }

    @Override
    public UserDtoResponse resetPassword(String username, String pwNew) {
        User user = userRepository.findUSerByUsername(username).orElseThrow(
                () -> new AppException(errorType.NotFoundUsername)
        );
        user.setPassword(passwordEncoder.encode(pwNew));
        log.info("Reset Mật khẩu thành công");
        return userMapper.mapToResponese(userRepository.save(user));
    }

    @Override
    public Set<UserDtoResponse> findUsersByGoogleIdNotNull() {
        Set<User> users = userRepository.findUsersByGoogleIdNotNull();
        return new HashSet<>(users.stream().map(userMapper::mapToResponese).toList());
    }


}
