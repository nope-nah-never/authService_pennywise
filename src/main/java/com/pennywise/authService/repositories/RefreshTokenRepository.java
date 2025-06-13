package com.pennywise.authService.repositories;

import com.pennywise.authService.db_entities.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity,String> {

    Optional<List<RefreshTokenEntity>> findByUserEmail(String email);

    @Modifying
    @Transactional
    @Query("UPDATE RefreshTokenEntity r SET r.usedAt = :usedAt, r.token = :token WHERE r.id = :id")
    int updateUsedAtAndTokenHashById(@Param("usedAt") Instant usedAt,
                                     @Param("token") String token,
                                     @Param("id") String id);
}
