package com.hominhnhut.WMN_BackEnd.mapper.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.request.RoleDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;


@Component
public class RoleMapper implements
        MyMapperInterFace<RoleDtoRequest, Role, RoleDtoResponse> {

    private final ModelMapper modelMapper;

    public RoleMapper(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }

    @Override
    public Role mapFromRequest(RoleDtoRequest R) {
        return this.modelMapper.map(R, Role.class);
    }

    @Override
    public RoleDtoResponse mapToResponese(Role role) {
        return this.modelMapper.map(role, RoleDtoResponse.class);
    }

    @Override
    public Role mapNewProvider(Role role, Role eUpdate) {
        return null;
    }
}
