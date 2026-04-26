package com.hfmlplatform.auth.repository;

import com.hfmlplatform.auth.model.Session;
import com.hfmlplatform.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<Session, UUID> {

    @Query("""
        SELECT s FROM Session s
        WHERE s.user = :user
        AND s.revokedAt IS NULL
        AND s.expiresAt > :now
        ORDER BY s.lastSeenAt ASC
        """)
    List<Session> findActiveByUserOrderByLastSeenAt(@Param("user") User user, @Param("now") OffsetDateTime now);

    @Query("""
        SELECT COUNT(s) FROM Session s
        WHERE s.user = :user
        AND s.revokedAt IS NULL
        AND s.expiresAt > :now
        """)
    long countActiveByUser(@Param("user") User user, @Param("now") OffsetDateTime now);

    @Modifying
    @Query("""
        UPDATE Session s
        SET s.revokedAt = :now, s.revokeReason = :reason
        WHERE s.user = :user
        AND s.revokedAt IS NULL
        """)
    void revokeAllByUser(@Param("user") User user, @Param("now") OffsetDateTime now, @Param("reason") String reason);

    @Modifying
    @Query("""
        UPDATE Session s
        SET s.revokedAt = :now, s.revokeReason = :reason
        WHERE s.revokedAt IS NULL
        AND s.expiresAt < :now
        """)
    void revokeExpired(@Param("now") OffsetDateTime now, @Param("reason") String reason);

    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :cutoff")
    void deleteOlderThan(@Param("cutoff") OffsetDateTime cutoff);
}
