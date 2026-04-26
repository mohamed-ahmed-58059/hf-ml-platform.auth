package com.hfmlplatform.auth.repository;

import com.hfmlplatform.auth.model.ServiceClient;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface ServiceClientRepository extends JpaRepository<ServiceClient, UUID> {
    Optional<ServiceClient> findByClientId(String clientId);
}
