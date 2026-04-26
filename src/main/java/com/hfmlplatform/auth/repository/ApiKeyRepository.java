package com.hfmlplatform.auth.repository;

import com.hfmlplatform.auth.model.ApiKey;
import com.hfmlplatform.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    @Query("SELECT k FROM ApiKey k WHERE k.keyHash = :hash AND k.status = 'active'")
    Optional<ApiKey> findActiveByKeyHash(@Param("hash") byte[] hash);

    @Query("SELECT k FROM ApiKey k WHERE k.user = :user AND k.status = 'active'")
    List<ApiKey> findActiveByUser(@Param("user") User user);

    boolean existsByUserAndName(User user, String name);
}
