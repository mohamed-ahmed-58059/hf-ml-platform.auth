package com.hfmlplatform.auth.scheduler;

import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

@Component
public class SessionCleanupScheduler {

    private static final Logger log = LoggerFactory.getLogger(SessionCleanupScheduler.class);

    private static final int TOKEN_RETENTION_DAYS   = 1;
    private static final int SESSION_RETENTION_DAYS = 7;

    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionRepository sessionRepository;

    public SessionCleanupScheduler(
            RefreshTokenRepository refreshTokenRepository,
            SessionRepository sessionRepository
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.sessionRepository = sessionRepository;
    }

    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanup() {
        OffsetDateTime now = OffsetDateTime.now();

        OffsetDateTime tokenCutoff   = now.minusDays(TOKEN_RETENTION_DAYS);
        OffsetDateTime sessionCutoff = now.minusDays(SESSION_RETENTION_DAYS);

        refreshTokenRepository.deleteOlderThan(tokenCutoff);
        sessionRepository.deleteOlderThan(sessionCutoff);

        log.info("Session cleanup complete — tokens before {}, sessions before {}", tokenCutoff, sessionCutoff);
    }
}
