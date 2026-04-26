package com.hfmlplatform.auth.repository;

import com.hfmlplatform.auth.model.Tier;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface TierRepository extends JpaRepository<Tier, UUID> {
    Optional<Tier> findByName(String name);
}
