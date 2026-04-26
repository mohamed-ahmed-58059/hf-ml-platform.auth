package com.hfmlplatform.auth.model;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false)
    private Session session;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token_hash", nullable = false, unique = true, columnDefinition = "bytea")
    private byte[] tokenHash;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private OffsetDateTime issuedAt;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private RefreshToken parent;

    @Column(name = "redeemed_at")
    private OffsetDateTime redeemedAt;

    @Column(name = "grace_until")
    private OffsetDateTime graceUntil;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    @Column(name = "revoke_reason")
    private String revokeReason;

    @PrePersist
    private void prePersist() {
        issuedAt = OffsetDateTime.now();
    }

    public UUID getId() { return id; }
    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public byte[] getTokenHash() { return tokenHash; }
    public void setTokenHash(byte[] tokenHash) { this.tokenHash = tokenHash; }
    public OffsetDateTime getIssuedAt() { return issuedAt; }
    public OffsetDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(OffsetDateTime expiresAt) { this.expiresAt = expiresAt; }
    public RefreshToken getParent() { return parent; }
    public void setParent(RefreshToken parent) { this.parent = parent; }
    public OffsetDateTime getRedeemedAt() { return redeemedAt; }
    public void setRedeemedAt(OffsetDateTime redeemedAt) { this.redeemedAt = redeemedAt; }
    public OffsetDateTime getGraceUntil() { return graceUntil; }
    public void setGraceUntil(OffsetDateTime graceUntil) { this.graceUntil = graceUntil; }
    public OffsetDateTime getRevokedAt() { return revokedAt; }
    public void setRevokedAt(OffsetDateTime revokedAt) { this.revokedAt = revokedAt; }
    public String getRevokeReason() { return revokeReason; }
    public void setRevokeReason(String revokeReason) { this.revokeReason = revokeReason; }

    public boolean isExpired() {
        return OffsetDateTime.now().isAfter(expiresAt);
    }

    public boolean isRedeemed() {
        return redeemedAt != null;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isWithinGracePeriod() {
        return graceUntil != null && OffsetDateTime.now().isBefore(graceUntil);
    }
}
