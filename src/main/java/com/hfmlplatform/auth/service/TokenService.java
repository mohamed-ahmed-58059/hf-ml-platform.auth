package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;
import java.security.SecureRandom;

@Service
public class TokenService {

    private final AppConfig config;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public TokenService(AppConfig config) {
        this.config = config;
    }

    @PostConstruct
    void init() throws Exception {
        String pem = config.getJwt().getPrivateKey()
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] der = Base64.getDecoder().decode(pem);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey = (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));

        var spec = new RSAPublicKeySpec(
                ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getModulus(),
                ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getPublicExponent()
        );
        publicKey = (RSAPublicKey) kf.generatePublic(spec);
    }

    public String mintToken(String subject, UUID sessionId) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(config.getJwt().getAccessTokenExpirySeconds());

        var builder = Jwts.builder()
                .subject(subject)
                .issuer(config.getJwt().getIssuer())
                .audience().add(config.getJwt().getAudience()).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(privateKey);

        if (sessionId != null) {
            builder.claim("sid", sessionId.toString());
        }

        return builder.compact();
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer(config.getJwt().getIssuer())
                .requireAudience(config.getJwt().getAudience())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public String generateRawRefreshToken() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public byte[] hashRefreshToken(String rawToken) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
    }
}
