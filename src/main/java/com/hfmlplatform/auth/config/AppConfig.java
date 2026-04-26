package com.hfmlplatform.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@ConfigurationProperties(prefix = "app")
@EnableScheduling
public class AppConfig {

    private Jwt jwt = new Jwt();
    private RefreshToken refreshToken = new RefreshToken();
    private Session session = new Session();
    private ApiKey apiKey = new ApiKey();
    private long reuseGracePeriodSeconds;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    public Jwt getJwt() { return jwt; }
    public RefreshToken getRefreshToken() { return refreshToken; }
    public Session getSession() { return session; }
    public ApiKey getApiKey() { return apiKey; }
    public long getReuseGracePeriodSeconds() { return reuseGracePeriodSeconds; }
    public void setReuseGracePeriodSeconds(long reuseGracePeriodSeconds) { this.reuseGracePeriodSeconds = reuseGracePeriodSeconds; }

    public static class Jwt {
        private String privateKey;
        private long accessTokenExpirySeconds;
        private String issuer;
        private String audience;

        public String getPrivateKey() { return privateKey; }
        public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }
        public long getAccessTokenExpirySeconds() { return accessTokenExpirySeconds; }
        public void setAccessTokenExpirySeconds(long accessTokenExpirySeconds) { this.accessTokenExpirySeconds = accessTokenExpirySeconds; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
    }

    public static class RefreshToken {
        private int expiryDays;

        public int getExpiryDays() { return expiryDays; }
        public void setExpiryDays(int expiryDays) { this.expiryDays = expiryDays; }
    }

    public static class Session {
        private int maxPerUser;

        public int getMaxPerUser() { return maxPerUser; }
        public void setMaxPerUser(int maxPerUser) { this.maxPerUser = maxPerUser; }
    }

    public static class ApiKey {
        private int maxPerUser;

        public int getMaxPerUser() { return maxPerUser; }
        public void setMaxPerUser(int maxPerUser) { this.maxPerUser = maxPerUser; }
    }
}
