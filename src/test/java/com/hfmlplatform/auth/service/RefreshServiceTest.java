package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import com.hfmlplatform.auth.dto.LoginResult;
import com.hfmlplatform.auth.model.RefreshToken;
import com.hfmlplatform.auth.model.Session;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshServiceTest {

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private SessionRepository sessionRepository;
    @Mock private TokenService tokenService;

    private AppConfig config;
    private RefreshService refreshService;

    @BeforeEach
    void setUp() {
        config = new AppConfig();
        config.setReuseGracePeriodSeconds(30);

        refreshService = new RefreshService(refreshTokenRepository, sessionRepository, tokenService, config);
    }

    @Test
    void refresh_rotatesToken() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        RefreshToken token = unusedToken(session, user);

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));
        when(tokenService.generateRawRefreshToken()).thenReturn("new-raw-token");
        when(tokenService.hashRefreshToken("new-raw-token")).thenReturn(new byte[33]);
        when(tokenService.mintToken(anyString(), any())).thenReturn("new-jwt");

        LoginResult result = refreshService.refresh("raw-token");

        assertNotNull(token.getRedeemedAt());
        assertNotNull(token.getGraceUntil());

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository, atLeast(2)).save(captor.capture());
        RefreshToken newToken = captor.getAllValues().stream()
                .filter(t -> t.getParent() == token)
                .findFirst().orElseThrow();
        assertEquals(token, newToken.getParent());
        assertEquals(session, newToken.getSession());
        assertEquals(user, newToken.getUser());

        verify(sessionRepository).save(session);

        assertEquals("new-jwt", result.accessToken());
        assertEquals("new-raw-token", result.rawRefreshToken());
        assertEquals(session.getId(), result.sessionId());
    }

    @Test
    void refresh_withinGracePeriod_returnsNewAccessTokenOnly() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        RefreshToken token = redeemedTokenWithinGrace(session, user);

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));
        when(tokenService.mintToken(anyString(), any())).thenReturn("new-jwt");

        LoginResult result = refreshService.refresh("raw-token");

        assertEquals("raw-token", result.rawRefreshToken());
        assertEquals("new-jwt", result.accessToken());

        verify(refreshTokenRepository, never()).save(any());
        verify(sessionRepository, never()).save(any());
        verify(tokenService, never()).generateRawRefreshToken();
    }

    @Test
    void refresh_outsideGracePeriod_revokesSessionAndThrows() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        RefreshToken token = redeemedTokenOutsideGrace(session, user);

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));

        assertThrows(RefreshService.TokenReuseDetectedException.class,
                () -> refreshService.refresh("raw-token"));

        verify(refreshTokenRepository).revokeAllBySession(eq(session), any(), eq("reuse_detected"));
        assertEquals("reuse_detected", session.getRevokeReason());
        assertNotNull(session.getRevokedAt());
        verify(sessionRepository).save(session);
    }

    @Test
    void refresh_throwsOnTokenNotFound() throws Exception {
        when(tokenService.hashRefreshToken("bad-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.empty());

        assertThrows(RefreshService.InvalidTokenException.class,
                () -> refreshService.refresh("bad-token"));
    }

    @Test
    void refresh_throwsOnRevokedToken() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        RefreshToken token = unusedToken(session, user);
        token.setRevokedAt(OffsetDateTime.now());

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));

        assertThrows(RefreshService.InvalidTokenException.class,
                () -> refreshService.refresh("raw-token"));
    }

    @Test
    void refresh_throwsOnInactiveSession() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        session.setRevokedAt(OffsetDateTime.now());
        RefreshToken token = unusedToken(session, user);

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));

        assertThrows(RefreshService.InvalidTokenException.class,
                () -> refreshService.refresh("raw-token"));
    }

    @Test
    void refresh_throwsOnExpiredToken() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        RefreshToken token = unusedToken(session, user);
        token.setExpiresAt(OffsetDateTime.now().minusDays(1));

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));

        assertThrows(RefreshService.InvalidTokenException.class,
                () -> refreshService.refresh("raw-token"));
    }

    @Test
    void refresh_newTokenInheritsExpiryFromParent() throws Exception {
        User user = userWithId();
        Session session = activeSession(user);
        RefreshToken token = unusedToken(session, user);
        OffsetDateTime originalExpiry = token.getExpiresAt();

        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(token));
        when(tokenService.generateRawRefreshToken()).thenReturn("new-raw-token");
        when(tokenService.hashRefreshToken("new-raw-token")).thenReturn(new byte[33]);
        when(tokenService.mintToken(anyString(), any())).thenReturn("new-jwt");

        refreshService.refresh("raw-token");

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository, atLeast(2)).save(captor.capture());
        RefreshToken newToken = captor.getAllValues().stream()
                .filter(t -> t.getParent() == token)
                .findFirst().orElseThrow();
        assertEquals(originalExpiry, newToken.getExpiresAt());
    }

    // --- Helpers ---

    private User userWithId() throws Exception {
        User user = new User();
        var field = User.class.getDeclaredField("id");
        field.setAccessible(true);
        field.set(user, UUID.randomUUID());
        return user;
    }

    private Session activeSession(User user) throws Exception {
        Session session = new Session();
        var field = Session.class.getDeclaredField("id");
        field.setAccessible(true);
        field.set(session, UUID.randomUUID());
        session.setUser(user);
        session.setExpiresAt(OffsetDateTime.now().plusDays(7));
        return session;
    }

    private RefreshToken unusedToken(Session session, User user) {
        RefreshToken token = new RefreshToken();
        token.setSession(session);
        token.setUser(user);
        token.setTokenHash(new byte[32]);
        token.setExpiresAt(OffsetDateTime.now().plusDays(7));
        return token;
    }

    private RefreshToken redeemedTokenWithinGrace(Session session, User user) {
        RefreshToken token = unusedToken(session, user);
        token.setRedeemedAt(OffsetDateTime.now().minusSeconds(10));
        token.setGraceUntil(OffsetDateTime.now().plusSeconds(20));
        return token;
    }

    private RefreshToken redeemedTokenOutsideGrace(Session session, User user) {
        RefreshToken token = unusedToken(session, user);
        token.setRedeemedAt(OffsetDateTime.now().minusMinutes(5));
        token.setGraceUntil(OffsetDateTime.now().minusMinutes(4));
        return token;
    }
}
