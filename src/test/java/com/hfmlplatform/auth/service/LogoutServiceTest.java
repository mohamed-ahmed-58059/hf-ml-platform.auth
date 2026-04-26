package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.model.Session;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LogoutServiceTest {

    @Mock private SessionRepository sessionRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private LogoutService logoutService;

    @BeforeEach
    void setUp() {
        logoutService = new LogoutService(sessionRepository, refreshTokenRepository);
    }

    @Test
    void logout_revokesSessionAndTokens() {
        UUID sessionId = UUID.randomUUID();
        Session session = new Session();
        session.setExpiresAt(OffsetDateTime.now().plusDays(7));

        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        logoutService.logout(sessionId);

        assertNotNull(session.getRevokedAt());
        assertEquals("logout", session.getRevokeReason());
        verify(refreshTokenRepository).revokeAllBySession(eq(session), any(), eq("logout"));
        verify(sessionRepository).save(session);
    }

    @Test
    void logout_doesNothingWhenSessionNotFound() {
        UUID sessionId = UUID.randomUUID();
        when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

        logoutService.logout(sessionId);

        verify(refreshTokenRepository, never()).revokeAllBySession(any(), any(), any());
        verify(sessionRepository, never()).save(any());
    }

    @Test
    void logout_revokesTokensBeforeSession() {
        UUID sessionId = UUID.randomUUID();
        Session session = new Session();
        session.setExpiresAt(OffsetDateTime.now().plusDays(7));

        when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(session));

        var order = inOrder(refreshTokenRepository, sessionRepository);
        logoutService.logout(sessionId);
        order.verify(refreshTokenRepository).revokeAllBySession(any(), any(), any());
        order.verify(sessionRepository).save(any());
    }

    @Test
    void logoutAll_revokesAllSessionsAndTokensForUser() {
        User user = new User();

        logoutService.logoutAll(user);

        verify(refreshTokenRepository).revokeAllByUser(eq(user), any(), eq("logout_all"));
        verify(sessionRepository).revokeAllByUser(eq(user), any(), eq("logout_all"));
    }

    @Test
    void logoutAll_revokesTokensBeforeSessions() {
        User user = new User();

        var order = inOrder(refreshTokenRepository, sessionRepository);
        logoutService.logoutAll(user);
        order.verify(refreshTokenRepository).revokeAllByUser(any(), any(), any());
        order.verify(sessionRepository).revokeAllByUser(any(), any(), any());
    }
}
