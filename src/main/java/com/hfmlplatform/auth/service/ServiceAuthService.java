package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.repository.ServiceClientRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class ServiceAuthService {

    private final ServiceClientRepository serviceClientRepository;
    private final TokenService tokenService;
    private final BCryptPasswordEncoder passwordEncoder;

    public ServiceAuthService(
            ServiceClientRepository serviceClientRepository,
            TokenService tokenService,
            BCryptPasswordEncoder passwordEncoder
    ) {
        this.serviceClientRepository = serviceClientRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
    }

    public String issueToken(String clientId, String clientSecret) {
        var client = serviceClientRepository.findByClientId(clientId)
                .orElseThrow(InvalidClientException::new);

        if (!client.isActive()) {
            throw new InvalidClientException();
        }

        if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
            throw new InvalidClientException();
        }

        // No session ID for service tokens
        return tokenService.mintToken(client.getClientId(), null);
    }

    public static class InvalidClientException extends RuntimeException {}
}
