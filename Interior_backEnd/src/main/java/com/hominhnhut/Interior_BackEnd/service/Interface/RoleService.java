package com.hominhnhut.WMN_BackEnd.service.Interface;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.request.RoleDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;

import java.util.List;
import java.util.Set;

public interface RoleService {

    List<RoleDtoResponse> findAll();

    RoleDtoResponse findById(Integer id);

    Role findRoleByRoleName(String roleName);

    RoleDtoResponse save(RoleDtoRequest request);

    RoleDtoResponse update(Integer idUpdate, RoleDtoRequest request);

    Set<RoleDtoResponse> getRoleOverview();

    void delete(Integer idDelete);

}

