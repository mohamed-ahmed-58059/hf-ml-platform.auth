package com.hfmlplatform.auth.repository;

import com.hfmlplatform.auth.model.RefreshToken;
import com.hfmlplatform.auth.model.Session;
import com.hfmlplatform.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT t FROM RefreshToken t WHERE t.tokenHash = :hash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("hash") byte[] hash);

    @Modifying
    @Query("""
        UPDATE RefreshToken t
        SET t.revokedAt = :now, t.revokeReason = :reason
        WHERE t.session = :session
        AND t.revokedAt IS NULL
        """)
    void revokeAllBySession(@Param("session") Session session, @Param("now") OffsetDateTime now, @Param("reason") String reason);

    @Modifying
    @Query("""
        UPDATE RefreshToken t
        SET t.revokedAt = :now, t.revokeReason = :reason
        WHERE t.user = :user
        AND t.revokedAt IS NULL
        """)
    void revokeAllByUser(@Param("user") User user, @Param("now") OffsetDateTime now, @Param("reason") String reason);

    @Modifying
    @Query("DELETE FROM RefreshToken t WHERE t.expiresAt < :cutoff")
    void deleteOlderThan(@Param("cutoff") OffsetDateTime cutoff);
}
