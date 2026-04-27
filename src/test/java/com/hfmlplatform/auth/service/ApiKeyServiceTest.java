package com.hfmlplatform.auth.service;

import com.hfmlplatform.auth.config.AppConfig;
import com.hfmlplatform.auth.model.ApiKey;
import com.hfmlplatform.auth.model.Tier;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.ApiKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApiKeyServiceTest {

    @Mock private ApiKeyRepository apiKeyRepository;
    @Mock private TokenService tokenService;

    private AppConfig config;
    private ApiKeyService apiKeyService;

    @BeforeEach
    void setUp() {
        config = new AppConfig();
        config.getApiKey().setMaxPerUser(10);

        apiKeyService = new ApiKeyService(apiKeyRepository, tokenService, config);
    }

    // --- createApiKey ---

    @Test
    void createApiKey_returnsRawKey() throws Exception {
        User user = userWithTier();

        when(apiKeyRepository.findActiveByUser(user)).thenReturn(List.of());
        when(apiKeyRepository.existsByUserAndNameAndStatus(user, "my-key", "active")).thenReturn(false);
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-api-key");
        when(tokenService.hashRefreshToken("raw-api-key")).thenReturn(new byte[32]);

        String result = apiKeyService.createApiKey(user, "my-key");

        assertEquals("raw-api-key", result);
    }

    @Test
    void createApiKey_savesKeyWithUsersDefaultTier() throws Exception {
        Tier tier = new Tier();
        User user = userWithTier(tier);
        byte[] hash = new byte[32];

        when(apiKeyRepository.findActiveByUser(user)).thenReturn(List.of());
        when(apiKeyRepository.existsByUserAndNameAndStatus(user, "my-key", "active")).thenReturn(false);
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-api-key");
        when(tokenService.hashRefreshToken("raw-api-key")).thenReturn(hash);

        apiKeyService.createApiKey(user, "my-key");

        ArgumentCaptor<ApiKey> captor = ArgumentCaptor.forClass(ApiKey.class);
        verify(apiKeyRepository).save(captor.capture());
        ApiKey saved = captor.getValue();

        assertEquals(user, saved.getUser());
        assertEquals(tier, saved.getTier());
        assertArrayEquals(hash, saved.getKeyHash());
        assertEquals("my-key", saved.getName());
    }

    @Test
    void createApiKey_throwsWhenCapReached() {
        User user = userWithTier();
        List<ApiKey> tenKeys = IntStream.range(0, 10)
                .mapToObj(i -> new ApiKey())
                .toList();

        when(apiKeyRepository.findActiveByUser(user)).thenReturn(tenKeys);

        assertThrows(ApiKeyService.ApiKeyCapExceededException.class,
                () -> apiKeyService.createApiKey(user, "my-key"));

        verify(apiKeyRepository, never()).save(any());
    }

    @Test
    void createApiKey_allowsNameReuseAfterRevoke() throws Exception {
        User user = userWithTier();

        when(apiKeyRepository.findActiveByUser(user)).thenReturn(List.of());
        when(apiKeyRepository.existsByUserAndNameAndStatus(user, "my-key", "active")).thenReturn(false);
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-api-key");
        when(tokenService.hashRefreshToken(any())).thenReturn(new byte[32]);

        assertDoesNotThrow(() -> apiKeyService.createApiKey(user, "my-key"));
    }

    @Test
    void createApiKey_throwsOnDuplicateKeyName() {
        User user = userWithTier();

        when(apiKeyRepository.findActiveByUser(user)).thenReturn(List.of());
        when(apiKeyRepository.existsByUserAndNameAndStatus(user, "my-key", "active")).thenReturn(true);

        assertThrows(ApiKeyService.DuplicateKeyNameException.class,
                () -> apiKeyService.createApiKey(user, "my-key"));

        verify(apiKeyRepository, never()).save(any());
    }

    @Test
    void createApiKey_allowsUpToCapKeys() throws Exception {
        User user = userWithTier();
        List<ApiKey> nineKeys = IntStream.range(0, 9)
                .mapToObj(i -> new ApiKey())
                .toList();

        when(apiKeyRepository.findActiveByUser(user)).thenReturn(nineKeys);
        when(apiKeyRepository.existsByUserAndNameAndStatus(user, "my-key", "active")).thenReturn(false);
        when(tokenService.generateRawRefreshToken()).thenReturn("raw-api-key");
        when(tokenService.hashRefreshToken(any())).thenReturn(new byte[32]);

        assertDoesNotThrow(() -> apiKeyService.createApiKey(user, "my-key"));
    }

    // --- listApiKeys ---

    @Test
    void listApiKeys_returnsActiveKeysForUser() {
        User user = new User();
        List<ApiKey> keys = IntStream.range(0, 3).mapToObj(i -> new ApiKey()).toList();
        when(apiKeyRepository.findActiveByUser(user)).thenReturn(keys);

        List<ApiKey> result = apiKeyService.listApiKeys(user);

        assertEquals(3, result.size());
        assertEquals(keys, result);
    }

    @Test
    void listApiKeys_returnsEmptyListWhenUserHasNoKeys() {
        User user = new User();
        when(apiKeyRepository.findActiveByUser(user)).thenReturn(List.of());

        List<ApiKey> result = apiKeyService.listApiKeys(user);

        assertTrue(result.isEmpty());
    }

    @Test
    void listApiKeys_doesNotReturnRevokedKeys() {
        User user = new User();
        when(apiKeyRepository.findActiveByUser(user)).thenReturn(List.of());

        apiKeyService.listApiKeys(user);

        verify(apiKeyRepository).findActiveByUser(user);
        verify(apiKeyRepository, never()).findAll();
    }

    // --- revokeApiKey ---

    @Test
    void revokeApiKey_setsStatusAndRevokedAt() throws Exception {
        User user = userWithId();
        UUID keyId = UUID.randomUUID();

        ApiKey apiKey = new ApiKey();
        apiKey.setUser(user);

        when(apiKeyRepository.findById(keyId)).thenReturn(Optional.of(apiKey));

        apiKeyService.revokeApiKey(user, keyId);

        assertEquals("revoked", apiKey.getStatus());
        assertNotNull(apiKey.getRevokedAt());
        verify(apiKeyRepository).save(apiKey);
    }

    @Test
    void revokeApiKey_doesNothingWhenKeyNotFound() throws Exception {
        User user = userWithId();
        UUID keyId = UUID.randomUUID();

        when(apiKeyRepository.findById(keyId)).thenReturn(Optional.empty());

        apiKeyService.revokeApiKey(user, keyId);

        verify(apiKeyRepository, never()).save(any());
    }

    @Test
    void revokeApiKey_throwsWhenKeyBelongsToOtherUser() throws Exception {
        User owner = userWithId();
        User otherUser = userWithId();
        UUID keyId = UUID.randomUUID();

        ApiKey apiKey = new ApiKey();
        apiKey.setUser(owner);

        when(apiKeyRepository.findById(keyId)).thenReturn(Optional.of(apiKey));

        assertThrows(ApiKeyService.ApiKeyNotFoundException.class,
                () -> apiKeyService.revokeApiKey(otherUser, keyId));

        verify(apiKeyRepository, never()).save(any());
    }

    @Test
    void revokeApiKey_revokedAtIsSetToApproximatelyNow() throws Exception {
        User user = userWithId();
        UUID keyId = UUID.randomUUID();

        ApiKey apiKey = new ApiKey();
        apiKey.setUser(user);

        when(apiKeyRepository.findById(keyId)).thenReturn(Optional.of(apiKey));

        OffsetDateTime before = OffsetDateTime.now();
        apiKeyService.revokeApiKey(user, keyId);
        OffsetDateTime after = OffsetDateTime.now();

        assertTrue(!apiKey.getRevokedAt().isBefore(before));
        assertTrue(!apiKey.getRevokedAt().isAfter(after));
    }

    // --- verify ---

    @Test
    void verify_returnsUserIdAndTierName() {
        UUID userId = UUID.randomUUID();
        User user = new User();
        try {
            var f = User.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(user, userId);
        } catch (Exception e) { fail(e); }

        Tier tier = new Tier();
        try {
            var f = Tier.class.getDeclaredField("name");
            f.setAccessible(true);
            f.set(tier, "premium");
        } catch (Exception e) { fail(e); }

        ApiKey apiKey = new ApiKey();
        apiKey.setUser(user);
        apiKey.setTier(tier);

        byte[] hash = new byte[32];
        String hashHex = HexFormat.of().formatHex(hash);
        when(apiKeyRepository.findActiveByKeyHash(hash)).thenReturn(Optional.of(apiKey));

        var result = apiKeyService.verify(hashHex);

        assertEquals(userId, result.userId());
        assertEquals("premium", result.tier());
    }

    @Test
    void verify_throwsWhenHashNotFound() {
        byte[] hash = new byte[32];
        String hashHex = HexFormat.of().formatHex(hash);
        when(apiKeyRepository.findActiveByKeyHash(hash)).thenReturn(Optional.empty());

        assertThrows(ApiKeyService.InvalidApiKeyException.class,
                () -> apiKeyService.verify(hashHex));
    }

    @Test
    void verify_throwsOnMalformedHex() {
        assertThrows(ApiKeyService.InvalidApiKeyException.class,
                () -> apiKeyService.verify("not-hex!"));
    }

    @Test
    void verify_throwsOnOddLengthHex() {
        assertThrows(ApiKeyService.InvalidApiKeyException.class,
                () -> apiKeyService.verify("abc"));
    }

    // --- Helpers ---

    private User userWithTier() {
        return userWithTier(new Tier());
    }

    private User userWithTier(Tier tier) {
        User user = new User();
        user.setDefaultTier(tier);
        return user;
    }

    private User userWithId() throws Exception {
        User user = new User();
        var field = User.class.getDeclaredField("id");
        field.setAccessible(true);
        field.set(user, UUID.randomUUID());
        return user;
    }
}
