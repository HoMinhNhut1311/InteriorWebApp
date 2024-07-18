package com.hominhnhut.WMN_BackEnd.config;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.request.RoleDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.UserDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.repository.RoleRepository;
import com.hominhnhut.WMN_BackEnd.repository.UserRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.RoleService;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class initConfig {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    @Transactional
    public void createAdmin() {
        // Create Role "ADMIN" if not exists
        if (userRepository.getUserByUsername("admin") == null) {
            Role role = roleRepository.getRoleByRoleName("ADMIN");
            if (role == null) {
            Role roleRequest = Role.builder()
                    .roleName("ADMIN")
                    .description("QTV")
                    .build();
                Role roleUser = Role.builder()
                        .roleName("USER")
                        .description("Nguoi dung")
                        .build();
                roleRepository.save(roleUser);
            role = roleRepository.saveAndFlush(roleRequest);
        }

        // Create Admin user if not exists
            Set<Role> roleNames = new HashSet<>();
            roleNames.add(role);
            User userRequest = User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("1"))
                    .roles(roleNames)
                    .build();
            userRepository.save(userRequest);
        }
    }
}
