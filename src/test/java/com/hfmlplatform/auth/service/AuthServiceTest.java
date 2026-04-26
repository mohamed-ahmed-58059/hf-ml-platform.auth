package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import com.hfmlplatform.auth.dto.LoginResult;
import com.hfmlplatform.auth.model.Session;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.model.Tier;
import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import com.hfmlplatform.auth.repository.TierRepository;
import com.hfmlplatform.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private SessionRepository sessionRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private TierRepository tierRepository;
    @Mock private TokenService tokenService;

    private BCryptPasswordEncoder passwordEncoder;
    private AppConfig config;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(4); // low cost for tests
        config = new AppConfig();
        config.getRefreshToken().setExpiryDays(7);
        config.getSession().setMaxPerUser(10);

        authService = new AuthService(
                userRepository, sessionRepository, refreshTokenRepository,
                tierRepository, tokenService, passwordEncoder, config
        );
    }

    // --- Signup ---

    @Test
    void signup_savesUserWithHashedPassword() {
        when(userRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(tierRepository.findByName("free")).thenReturn(Optional.of(new Tier()));

        authService.signup("user@example.com", "password123");

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        User saved = captor.getValue();
        assertEquals("user@example.com", saved.getEmail());
        assertTrue(passwordEncoder.matches("password123", saved.getPasswordHash()));
    }

    @Test
    void signup_throwsOnDuplicateEmail() {
        when(userRepository.existsByEmail("user@example.com")).thenReturn(true);

        assertThrows(AuthService.EmailAlreadyExistsException.class,
                () -> authService.signup("user@example.com", "password123"));

        verify(userRepository, never()).save(any());
    }

    // --- Login ---

    @Test
    void login_returnsLoginResult() throws Exception {
        User user = userWithPassword("password123");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(sessionRepository.findActiveByUserOrderByLastSeenAt(eq(user), any())).thenReturn(List.of());
        when(sessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-token");
        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(tokenService.mintToken(anyString(), any())).thenReturn("jwt-token");

        LoginResult result = authService.login("user@example.com", "password123", null, "127.0.0.1", "curl");

        assertNotNull(result);
        assertEquals("jwt-token", result.accessToken());
        assertEquals("raw-token", result.rawRefreshToken());
    }

    @Test
    void login_throwsOnUnknownEmail() {
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

        assertThrows(AuthService.InvalidCredentialsException.class,
                () -> authService.login("unknown@example.com", "password123", null, null, null));
    }

    @Test
    void login_throwsOnWrongPassword() throws Exception {
        User user = userWithPassword("correct-password");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        assertThrows(AuthService.InvalidCredentialsException.class,
                () -> authService.login("user@example.com", "wrong-password", null, null, null));
    }

    @Test
    void login_evictsOldestSessionWhenCapReached() throws Exception {
        User user = userWithPassword("password123");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        List<Session> activeSessions = activeSessions(user, 10);
        when(sessionRepository.findActiveByUserOrderByLastSeenAt(eq(user), any())).thenReturn(activeSessions);
        when(sessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-token");
        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(tokenService.mintToken(anyString(), any())).thenReturn("jwt-token");

        authService.login("user@example.com", "password123", null, null, null);

        Session oldest = activeSessions.getFirst();
        assertEquals("session_cap", oldest.getRevokeReason());
        assertNotNull(oldest.getRevokedAt());
    }

    @Test
    void login_revokesExistingSessionOnReLogin() throws Exception {
        User user = userWithPassword("password123");
        UUID existingSessionId = UUID.randomUUID();

        Session existingSession = new Session();
        existingSession.setUser(user);
        existingSession.setExpiresAt(OffsetDateTime.now().plusDays(7));

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(sessionRepository.findById(existingSessionId)).thenReturn(Optional.of(existingSession));
        when(sessionRepository.findActiveByUserOrderByLastSeenAt(eq(user), any())).thenReturn(List.of());
        when(sessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-token");
        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(tokenService.mintToken(anyString(), any())).thenReturn("jwt-token");

        authService.login("user@example.com", "password123", existingSessionId, null, null);

        assertEquals("re-login", existingSession.getRevokeReason());
        assertNotNull(existingSession.getRevokedAt());
    }

    @Test
    void login_setsIpAndUserAgent() throws Exception {
        User user = userWithPassword("password123");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(sessionRepository.findActiveByUserOrderByLastSeenAt(eq(user), any())).thenReturn(List.of());
        when(sessionRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-token");
        when(tokenService.hashRefreshToken("raw-token")).thenReturn(new byte[32]);
        when(tokenService.mintToken(anyString(), any())).thenReturn("jwt-token");

        authService.login("user@example.com", "password123", null, "192.168.1.1", "Mozilla/5.0");

        ArgumentCaptor<Session> captor = ArgumentCaptor.forClass(Session.class);
        verify(sessionRepository, atLeastOnce()).save(captor.capture());

        Session newSession = captor.getAllValues().stream()
                .filter(s -> s.getIp() != null)
                .findFirst().orElseThrow();

        assertEquals("192.168.1.1", newSession.getIp());
        assertEquals("Mozilla/5.0", newSession.getUserAgent());
    }

    // --- Helpers ---

    private User userWithPassword(String password) throws Exception {
        User user = new User();
        var idField = User.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(user, UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setPasswordHash(passwordEncoder.encode(password));
        return user;
    }

    private List<Session> activeSessions(User user, int count) {
        return java.util.stream.IntStream.range(0, count).mapToObj(i -> {
            Session s = new Session();
            s.setUser(user);
            s.setExpiresAt(OffsetDateTime.now().plusDays(7));
            return s;
        }).collect(java.util.stream.Collectors.toList());
    }
}
