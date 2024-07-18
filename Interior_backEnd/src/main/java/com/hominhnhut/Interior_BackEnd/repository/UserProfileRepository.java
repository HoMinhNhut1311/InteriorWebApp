package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserProfileRepository extends JpaRepository<UserProfile,String> {

    Optional<UserProfile> getUserProfileByProfileEmail(String email);
    boolean existsByProfileEmail(String email);
}
