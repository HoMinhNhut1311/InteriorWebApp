package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import jakarta.persistence.NamedNativeQuery;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.Set;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Role getRoleByRoleName(String roleName);
    Optional<Role> findRoleByRoleName(String roleName);

    @Query(name = "GetRoleDtoResponse",nativeQuery = true)
    RoleDtoResponse getRoleResponseByRoleId(@Param("role_id") Integer roleId);


    @Query(value = "select count(users_roles.user_id) " +
            "from users_roles where users_roles.role_id = :roleId", nativeQuery = true)
    Integer getCountUserByRoleId(@Param("roleId") Integer roleID);

    @Query(value = "SELECT COUNT(user_id) from users_roles",nativeQuery = true)
    Integer getCountUser();


}
