package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.model.ServiceClient;
import com.hfmlplatform.auth.repository.ServiceClientRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ServiceAuthServiceTest {

    @Mock private ServiceClientRepository serviceClientRepository;
    @Mock private TokenService tokenService;

    private BCryptPasswordEncoder passwordEncoder;
    private ServiceAuthService serviceAuthService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(4);
        serviceAuthService = new ServiceAuthService(serviceClientRepository, tokenService, passwordEncoder);
    }

    @Test
    void issueToken_returnsTokenForValidClient() {
        ServiceClient client = clientWithSecret("correct-secret");
        when(serviceClientRepository.findByClientId("rate-limiter")).thenReturn(Optional.of(client));
        when(tokenService.mintToken("rate-limiter", null)).thenReturn("service-jwt");

        String token = serviceAuthService.issueToken("rate-limiter", "correct-secret");

        assertEquals("service-jwt", token);
    }

    @Test
    void issueToken_mintsTokenWithClientIdAsSubjectAndNoSessionId() {
        ServiceClient client = clientWithSecret("correct-secret");
        when(serviceClientRepository.findByClientId("rate-limiter")).thenReturn(Optional.of(client));
        when(tokenService.mintToken(anyString(), any())).thenReturn("service-jwt");

        serviceAuthService.issueToken("rate-limiter", "correct-secret");

        verify(tokenService).mintToken("rate-limiter", null);
    }

    @Test
    void issueToken_throwsOnUnknownClientId() {
        when(serviceClientRepository.findByClientId("unknown")).thenReturn(Optional.empty());

        assertThrows(ServiceAuthService.InvalidClientException.class,
                () -> serviceAuthService.issueToken("unknown", "secret"));

        verify(tokenService, never()).mintToken(any(), any());
    }

    @Test
    void issueToken_throwsOnRevokedClient() {
        ServiceClient client = clientWithSecret("correct-secret");
        client.setRevokedAt(OffsetDateTime.now());
        when(serviceClientRepository.findByClientId("rate-limiter")).thenReturn(Optional.of(client));

        assertThrows(ServiceAuthService.InvalidClientException.class,
                () -> serviceAuthService.issueToken("rate-limiter", "correct-secret"));

        verify(tokenService, never()).mintToken(any(), any());
    }

    @Test
    void issueToken_throwsOnWrongSecret() {
        ServiceClient client = clientWithSecret("correct-secret");
        when(serviceClientRepository.findByClientId("rate-limiter")).thenReturn(Optional.of(client));

        assertThrows(ServiceAuthService.InvalidClientException.class,
                () -> serviceAuthService.issueToken("rate-limiter", "wrong-secret"));

        verify(tokenService, never()).mintToken(any(), any());
    }

    @Test
    void issueToken_sameErrorForUnknownClientAndWrongSecret() {
        when(serviceClientRepository.findByClientId("unknown")).thenReturn(Optional.empty());
        ServiceClient client = clientWithSecret("correct-secret");
        when(serviceClientRepository.findByClientId("rate-limiter")).thenReturn(Optional.of(client));

        var exUnknown = assertThrows(ServiceAuthService.InvalidClientException.class,
                () -> serviceAuthService.issueToken("unknown", "secret"));
        var exWrong = assertThrows(ServiceAuthService.InvalidClientException.class,
                () -> serviceAuthService.issueToken("rate-limiter", "wrong-secret"));

        assertEquals(exUnknown.getClass(), exWrong.getClass());
    }

    // --- Helpers ---

    private ServiceClient clientWithSecret(String plainSecret) {
        ServiceClient client = new ServiceClient();
        client.setClientId("rate-limiter");
        client.setName("Rate Limiter");
        client.setClientSecretHash(passwordEncoder.encode(plainSecret));
        return client;
    }
}
