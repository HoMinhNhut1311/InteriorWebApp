package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.Role;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface UserRepository extends JpaRepository<User, String> {

    User getUserByUsername(String username);

    Optional<User> getUserByUsernameAndPassword(String username, String password);

    Optional<User> findUSerByUsername(String userName);

    Page<User> findAllByUsernameContaining(String usernameContain, Pageable pageable);


    Set<User> getUsersByRoles(Set<Role> roles);

    @Query(value = "SELECT u.* FROM users u " +
            "INNER JOIN users_roles ur ON u.user_id = ur.user_id\n" +
            "WHERE ur.role_id = :roleId",nativeQuery = true)
    Page<User> getUsersByRoleId(@Param("roleId") Integer roleId, Pageable pageable);
    boolean existsByUsername(String username);

    Optional<User> findUsersByGoogleId(String googleId);
    Set<User> findUsersByGoogleIdNotNull();


}
