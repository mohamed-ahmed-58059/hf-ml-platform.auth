package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import com.hfmlplatform.auth.dto.LoginResult;
import com.hfmlplatform.auth.model.RefreshToken;
import com.hfmlplatform.auth.model.Session;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import com.hfmlplatform.auth.repository.TierRepository;
import com.hfmlplatform.auth.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TierRepository tierRepository;
    private final TokenService tokenService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AppConfig config;

    public AuthService(
            UserRepository userRepository,
            SessionRepository sessionRepository,
            RefreshTokenRepository refreshTokenRepository,
            TierRepository tierRepository,
            TokenService tokenService,
            BCryptPasswordEncoder passwordEncoder,
            AppConfig config
    ) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tierRepository = tierRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.config = config;
    }

    @Transactional
    public void signup(String email, String password) {
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException();
        }
        var defaultTier = tierRepository.findByName("free")
                .orElseThrow(() -> new IllegalStateException("free tier not found"));
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setDefaultTier(defaultTier);
        userRepository.save(user);
    }

    @Transactional
    public LoginResult login(String email, String password, UUID existingSessionId, String ip, String userAgent) throws Exception {
        User user = userRepository.findByEmail(email)
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        OffsetDateTime now = OffsetDateTime.now();

        // Revoke the previous session if the client sent a valid sid cookie
        if (existingSessionId != null) {
            sessionRepository.findById(existingSessionId).ifPresent(previous -> {
                if (previous.getUser().getId().equals(user.getId()) && previous.isActive()) {
                    refreshTokenRepository.revokeAllBySession(previous, now, "re-login");
                    previous.setRevokedAt(now);
                    previous.setRevokeReason("re-login");
                    sessionRepository.save(previous);
                }
            });
        }

        // Enforce session cap before creating a new session
        List<Session> activeSessions = sessionRepository.findActiveByUserOrderByLastSeenAt(user, now);
        if (activeSessions.size() >= config.getSession().getMaxPerUser()) {
            Session oldest = activeSessions.getFirst();
            refreshTokenRepository.revokeAllBySession(oldest, now, "session_cap");
            oldest.setRevokedAt(now);
            oldest.setRevokeReason("session_cap");
            sessionRepository.save(oldest);
        }

        // Create new session
        Session session = new Session();
        session.setUser(user);
        session.setExpiresAt(now.plusDays(config.getRefreshToken().getExpiryDays()));
        session.setIp(ip);
        session.setUserAgent(userAgent);
        sessionRepository.save(session);

        // Issue refresh token
        String rawRefreshToken = tokenService.generateRawRefreshToken();
        byte[] tokenHash = tokenService.hashRefreshToken(rawRefreshToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setSession(session);
        refreshToken.setUser(user);
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setExpiresAt(now.plusDays(config.getRefreshToken().getExpiryDays()));
        refreshTokenRepository.save(refreshToken);

        String accessToken = tokenService.mintToken(user.getId().toString(), session.getId());

        return new LoginResult(session.getId(), accessToken, rawRefreshToken);
    }

    public static class EmailAlreadyExistsException extends RuntimeException {}
    public static class InvalidCredentialsException extends RuntimeException {}
}
