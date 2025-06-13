package com.pennywise.authService.repositories;

import com.pennywise.authService.db_entities.PassResetTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PassResetTokenEntity, Integer> {
}
