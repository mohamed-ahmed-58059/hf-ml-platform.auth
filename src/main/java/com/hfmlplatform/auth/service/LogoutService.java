package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.UUID;

@Service
public class LogoutService {

    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public LogoutService(SessionRepository sessionRepository, RefreshTokenRepository refreshTokenRepository) {
        this.sessionRepository = sessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional
    public void logout(UUID sessionId) {
        sessionRepository.findById(sessionId).ifPresent(session -> {
            OffsetDateTime now = OffsetDateTime.now();
            refreshTokenRepository.revokeAllBySession(session, now, "logout");
            session.setRevokedAt(now);
            session.setRevokeReason("logout");
            sessionRepository.save(session);
        });
    }

    @Transactional
    public void logoutAll(User user) {
        OffsetDateTime now = OffsetDateTime.now();
        refreshTokenRepository.revokeAllByUser(user, now, "logout_all");
        sessionRepository.revokeAllByUser(user, now, "logout_all");
    }
}
