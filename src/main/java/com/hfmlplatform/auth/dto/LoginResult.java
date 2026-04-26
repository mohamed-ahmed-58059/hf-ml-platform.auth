package com.hfmlplatform.auth.dto;

import java.util.UUID;

public record LoginResult(
        UUID sessionId,
        String accessToken,
        String rawRefreshToken
) {}
