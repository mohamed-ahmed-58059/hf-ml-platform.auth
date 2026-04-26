package com.hfmlplatform.auth.model;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.util.UUID;

@Entity
@Table(name = "tiers")
public class Tier {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private int capacity;

    @Column(name = "refill_per_sec", nullable = false, precision = 10, scale = 4)
    private BigDecimal refillPerSec;

    @Column(name = "requests_per_min", nullable = false)
    private int requestsPerMin;

    @Column(nullable = false)
    private int version;

    public UUID getId() { return id; }
    public String getName() { return name; }
    public int getCapacity() { return capacity; }
    public BigDecimal getRefillPerSec() { return refillPerSec; }
    public int getRequestsPerMin() { return requestsPerMin; }
    public int getVersion() { return version; }
}
