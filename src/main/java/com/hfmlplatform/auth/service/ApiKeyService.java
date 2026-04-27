package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import com.hfmlplatform.auth.model.ApiKey;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.ApiKeyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private final TokenService tokenService;
    private final AppConfig config;

    public ApiKeyService(
            ApiKeyRepository apiKeyRepository,
            TokenService tokenService,
            AppConfig config
    ) {
        this.apiKeyRepository = apiKeyRepository;
        this.tokenService = tokenService;
        this.config = config;
    }

    @Transactional
    public String createApiKey(User user, String keyName) throws Exception {
        var tier = user.getDefaultTier();

        if (apiKeyRepository.findActiveByUser(user).size() >= config.getApiKey().getMaxPerUser()) {
            throw new ApiKeyCapExceededException();
        }

        if (apiKeyRepository.existsByUserAndName(user, keyName)) {
            throw new DuplicateKeyNameException();
        }

        String rawKey = tokenService.generateRawRefreshToken();
        byte[] keyHash = tokenService.hashRefreshToken(rawKey);

        ApiKey apiKey = new ApiKey();
        apiKey.setUser(user);
        apiKey.setTier(tier);
        apiKey.setKeyHash(keyHash);
        apiKey.setName(keyName);
        apiKeyRepository.save(apiKey);

        return rawKey;
    }

    public List<ApiKey> listApiKeys(User user) {
        return apiKeyRepository.findActiveByUser(user);
    }

    @Transactional
    public void revokeApiKey(User user, UUID apiKeyId) {
        apiKeyRepository.findById(apiKeyId).ifPresent(apiKey -> {
            if (!apiKey.getUser().getId().equals(user.getId())) {
                throw new ApiKeyNotFoundException();
            }
            apiKey.setStatus("revoked");
            apiKey.setRevokedAt(OffsetDateTime.now());
            apiKeyRepository.save(apiKey);
        });
    }

    public ApiKeyVerification verify(String keyHashHex) {
        byte[] hash;
        try {
            hash = HexFormat.of().parseHex(keyHashHex);
        } catch (IllegalArgumentException e) {
            throw new InvalidApiKeyException();
        }
        var apiKey = apiKeyRepository.findActiveByKeyHash(hash)
                .orElseThrow(InvalidApiKeyException::new);
        return new ApiKeyVerification(apiKey.getUser().getId(), apiKey.getTier().getName());
    }

    public record ApiKeyVerification(UUID userId, String tier) {}

    public static class TierNotFoundException extends RuntimeException {}
    public static class ApiKeyNotFoundException extends RuntimeException {}
    public static class ApiKeyCapExceededException extends RuntimeException {}
    public static class DuplicateKeyNameException extends RuntimeException {}
    public static class InvalidApiKeyException extends RuntimeException {}
}
