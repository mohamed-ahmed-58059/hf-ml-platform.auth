package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import com.hfmlplatform.auth.dto.LoginResult;
import com.hfmlplatform.auth.model.RefreshToken;
import com.hfmlplatform.auth.repository.RefreshTokenRepository;
import com.hfmlplatform.auth.repository.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

@Service
public class RefreshService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionRepository sessionRepository;
    private final TokenService tokenService;
    private final AppConfig config;

    public RefreshService(
            RefreshTokenRepository refreshTokenRepository,
            SessionRepository sessionRepository,
            TokenService tokenService,
            AppConfig config
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.sessionRepository = sessionRepository;
        this.tokenService = tokenService;
        this.config = config;
    }

    @Transactional
    public LoginResult refresh(String rawRefreshToken) throws Exception {
        byte[] hash = tokenService.hashRefreshToken(rawRefreshToken);
        OffsetDateTime now = OffsetDateTime.now();

        RefreshToken token = refreshTokenRepository.findByTokenHashForUpdate(hash)
                .orElseThrow(InvalidTokenException::new);

        if (token.isRevoked() || !token.getSession().isActive()) {
            throw new InvalidTokenException();
        }

        if (token.isExpired()) {
            throw new InvalidTokenException();
        }

        if (token.isRedeemed()) {
            if (token.isWithinGracePeriod()) {
                // Concurrent request within grace window — issue a new access token only, don't rotate
                String accessToken = tokenService.mintToken(
                        token.getUser().getId().toString(),
                        token.getSession().getId()
                );
                return new LoginResult(token.getSession().getId(), accessToken, rawRefreshToken);
            } else {
                // Reuse detected outside grace period — revoke entire session
                refreshTokenRepository.revokeAllBySession(token.getSession(), now, "reuse_detected");
                token.getSession().setRevokedAt(now);
                token.getSession().setRevokeReason("reuse_detected");
                sessionRepository.save(token.getSession());
                throw new TokenReuseDetectedException();
            }
        }

        // Valid unused token — rotate
        token.setRedeemedAt(now);
        token.setGraceUntil(now.plusSeconds(config.getReuseGracePeriodSeconds()));
        refreshTokenRepository.save(token);

        String newRawToken = tokenService.generateRawRefreshToken();
        byte[] newHash = tokenService.hashRefreshToken(newRawToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setSession(token.getSession());
        newToken.setUser(token.getUser());
        newToken.setTokenHash(newHash);
        newToken.setExpiresAt(token.getExpiresAt());
        newToken.setParent(token);
        refreshTokenRepository.save(newToken);

        token.getSession().setLastSeenAt(now);
        sessionRepository.save(token.getSession());

        String accessToken = tokenService.mintToken(
                token.getUser().getId().toString(),
                token.getSession().getId()
        );

        return new LoginResult(token.getSession().getId(), accessToken, newRawToken);
    }

    public static class InvalidTokenException extends RuntimeException {}
    public static class TokenReuseDetectedException extends RuntimeException {}
}
