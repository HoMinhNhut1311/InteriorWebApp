package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.request.RoleDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import com.hominhnhut.WMN_BackEnd.repository.RoleRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.RoleService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    RoleRepository roleRepository;

    MyMapperInterFace<RoleDtoRequest, Role , RoleDtoResponse> roleMapper;



    public List<RoleDtoResponse> findAll() {
        return this.roleRepository.findAll().stream()
                .map(
                        this.roleMapper::mapToResponese
                ).collect(Collectors.toList());
    };

    public RoleDtoResponse findById(Integer id) {
        return this.roleRepository.findById(id).
                map(this.roleMapper::mapToResponese)
                .orElseThrow(
                        () -> new AppException(errorType.notFound)
                );
    }

    @Override
    public Role findRoleByRoleName(String roleName) {
        return roleRepository.getRoleByRoleName(roleName);
    }

    public RoleDtoResponse save(RoleDtoRequest request) {
        Role role = this.roleMapper.mapFromRequest(request);
        return this.roleMapper.mapToResponese(this.roleRepository.save(role));
    }

    public RoleDtoResponse update(Integer idUpdate,RoleDtoRequest request) {
        Role roleExist = this.roleRepository.findById(idUpdate).orElseThrow(
                () -> new AppException(errorType.notFound)
        );

        Role role = this.roleMapper.mapFromRequest(request);
        role.setRoleId(idUpdate);
        this.roleRepository.saveAndFlush(role);
        return this.roleMapper.mapToResponese(role);
    }

    public Set<RoleDtoResponse> getRoleOverview() {
        List<Role> roles = roleRepository.findAll();

        Set<RoleDtoResponse> roleDtoResponses = new HashSet<>();
        roles.forEach((role) -> {
            RoleDtoResponse response = new RoleDtoResponse();
            response.setRoleName(role.getRoleName());
            response.setDescription(role.getDescription());
            response.setRoleId(role.getRoleId());
            response.setCount(roleRepository.
                    getCountUserByRoleId(role.getRoleId()));
            roleDtoResponses.add(response);
        });
        return roleDtoResponses;
    }


    public void delete(Integer idDelete) {
        Role role = this.roleRepository.findById(idDelete).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        this.roleRepository.delete(role);
    }

}
