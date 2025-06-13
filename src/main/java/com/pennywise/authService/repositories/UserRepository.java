package com.pennywise.authService.repositories;

import com.pennywise.authService.db_entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    UserEntity findByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE UserEntity u SET u.isVerified = :status WHERE u.email = :email")
    void updateVerificationStatusByEmail(@Param("email") String email, @Param("status") boolean status);
}
