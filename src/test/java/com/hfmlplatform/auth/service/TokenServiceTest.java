package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class TokenServiceTest {

    private static final String TEST_PRIVATE_KEY = """
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNeGsBsWqdRS78
            Rqn14SS5KVGTLs1HF1Qqq9G68s8Q+/lvFohUoZLOI0CK6WDXFi6VhDTxR664f783
            O0Wf4sMZxiPohNNPVQ4HT6bxPJqciYEk2O+eHahmzmrVh3oGmXOwmh+Gl/lmcz6w
            ck24cxEvjxllCma0HEANrvkD9KbVUVXi4Sle4RAcLrhNuy+KsvSeAReQYPWBgqgl
            KgFFDNC5uxMbJZwgpUZOLrdrFbKcT5faEfXr2pZ6LN2hCqRxxAwP/Bsz0dSNX/EU
            00FN2z7FsldttUv169zHOy7ay/VNU0CAKVJPOgObiNj9z9EyyfoddXM532mIE9Pi
            u9dWC0+xAgMBAAECggEAA2gvTFYKLZAHq4ve6cZ9yWqTn3Oxl7EAPGgKsxgueqGI
            cy+IofnwKXNTSX68VjTsQBQnTqY9lw2wiUzhBnkCEaIiP3L8QDCNF9aU746LlKu1
            E5hld010i3rhVMbtKxdRk2+3kaWIT2DRu8ZM7xCKWen2BrQDUpQZlzRfCxE+kVJZ
            qgA2FChqwIT+AEmW7QO8Tvrrg0n2xvzBCt0vR2B14GDgFyfZAJ6eu9RmDCZ9w3UG
            5ppSoRHnXdnshl9GM/YTeFd7QFD3KS+ln9okaj9+BQWYlq20ixBRFBdKHqDMRUVw
            +ie7SlMlhlWUmqm78bRsixSK+7VjMPXAdnnG6pQ/BwKBgQDABL60NEyk7r3C37fQ
            M3o4iJlOTlypd6Ccjvb5iJVslSRTGUfWaFIILuMeCOcm+ncRV88oCysTNKKKOXnn
            Q+mrDIupI8M9mNXcm1gYiZgt8UsZLJzmaFg3CA0oPwnz9Zt9PjjAsDyZ5Mb5BOtO
            f+uLuCZx/k6NzrO9HO2KIMaXzwKBgQC8m+Vs2blNIdY3exaGrGpMmeK38yBlQJqo
            AmHZsaQqeX34j7Qw7FbJQ/J9gngyuP5GsdBqavzw6OjX8EzMKR7GB1Lch/PQbjRG
            SUfcWxtMsgOu5/vUa/FoiAVUAeBBdxn/0tTXbDchv7njb657CVvmtwLLBGPlg2eL
            5IlJb5oAfwKBgEFMm8nOi03/fnrZ97mO9/5nvbLahTqAWxdCqwya/S2q3mqAC2UH
            nvX3c/cP0gP4Yyt7sBAPFDv4x1m4SBN0je9EWe5QIiI9amUWUvQtPppJF1/dQxI7
            49v7GfZY0bqsCI+j7Eri5Aj1uxCOMrNEX0bpffGAKRiidY9XWhSCJucTAoGAbDZB
            pncwkqmEP2a2oOQRRQvRgVrTzmQHl7duLrl2CAyWkuLYLm2ayXTbjtkpX2i2MxdY
            DYZ+wzXOSf6MAWLiThnrl63E3GQuR9lJiosXGaTU6igdW13nLuNDs1Q0Nzs/RoDP
            Lx3eb9WRsITmJZ9UBAYiaxqEuizvXtrrTZ/jSr8CgYEAtQA9tJWIyv2eJF/OpNOA
            G8ZG9htp/Hros7eLJ3ucwE1LSzIRsjgPXOFhdlUD566NEHqZouRAdk7iyQbzyjUE
            mBanw5l6IcSNbgC+YZI3yvYvOwi92bHCDEK8JdpXJ3ckL8gjHpA9llqNT4o5FeYh
            oDmgMoBuR/CJLZNR7iAyrls=
            """;

    private TokenService tokenService;

    @BeforeEach
    void setUp() throws Exception {
        AppConfig config = new AppConfig();
        config.getJwt().setPrivateKey("-----BEGIN PRIVATE KEY-----\n" + TEST_PRIVATE_KEY + "-----END PRIVATE KEY-----");
        config.getJwt().setAccessTokenExpirySeconds(900);
        config.getJwt().setIssuer("auth-service");
        config.getJwt().setAudience("api");

        tokenService = new TokenService(config);
        tokenService.init();
    }

    @Test
    void mintToken_returnsNonNullToken() {
        String token = tokenService.mintToken("user-123", UUID.randomUUID());
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void mintToken_withSessionId_setsSubjectAndSid() {
        UUID sessionId = UUID.randomUUID();
        String token = tokenService.mintToken("user-123", sessionId);

        Claims claims = tokenService.parseToken(token);

        assertEquals("user-123", claims.getSubject());
        assertEquals(sessionId.toString(), claims.get("sid", String.class));
    }

    @Test
    void mintToken_withoutSessionId_hasNoSid() {
        String token = tokenService.mintToken("rate-limiter", null);

        Claims claims = tokenService.parseToken(token);

        assertEquals("rate-limiter", claims.getSubject());
        assertNull(claims.get("sid"));
    }

    @Test
    void mintToken_setsCorrectIssuerAndAudience() {
        String token = tokenService.mintToken("user-123", null);
        Claims claims = tokenService.parseToken(token);

        assertEquals("auth-service", claims.getIssuer());
        assertTrue(claims.getAudience().contains("api"));
    }

    @Test
    void parseToken_throwsOnTamperedToken() {
        String token = tokenService.mintToken("user-123", null);
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";

        assertThrows(JwtException.class, () -> tokenService.parseToken(tampered));
    }

    @Test
    void parseToken_throwsOnWrongIssuer() throws Exception {
        AppConfig otherConfig = new AppConfig();
        otherConfig.getJwt().setPrivateKey("-----BEGIN PRIVATE KEY-----\n" + TEST_PRIVATE_KEY + "-----END PRIVATE KEY-----");
        otherConfig.getJwt().setAccessTokenExpirySeconds(900);
        otherConfig.getJwt().setIssuer("other-service");
        otherConfig.getJwt().setAudience("api");

        TokenService otherService = new TokenService(otherConfig);
        otherService.init();

        String token = otherService.mintToken("user-123", null);
        assertThrows(JwtException.class, () -> tokenService.parseToken(token));
    }

    @Test
    void generateRawRefreshToken_returns128CharHexString() {
        String token = tokenService.generateRawRefreshToken();

        assertEquals(128, token.length());
        assertTrue(token.matches("[0-9a-f]+"));
    }

    @Test
    void generateRawRefreshToken_isUnique() {
        String token1 = tokenService.generateRawRefreshToken();
        String token2 = tokenService.generateRawRefreshToken();

        assertNotEquals(token1, token2);
    }

    @Test
    void hashRefreshToken_isDeterministic() throws Exception {
        String raw = tokenService.generateRawRefreshToken();
        byte[] hash1 = tokenService.hashRefreshToken(raw);
        byte[] hash2 = tokenService.hashRefreshToken(raw);

        assertArrayEquals(hash1, hash2);
    }

    @Test
    void hashRefreshToken_differentInputsProduceDifferentHashes() throws Exception {
        byte[] hash1 = tokenService.hashRefreshToken("token-one");
        byte[] hash2 = tokenService.hashRefreshToken("token-two");

        assertFalse(java.util.Arrays.equals(hash1, hash2));
    }

    @Test
    void getPublicKey_returnsNonNull() {
        assertNotNull(tokenService.getPublicKey());
    }
}
