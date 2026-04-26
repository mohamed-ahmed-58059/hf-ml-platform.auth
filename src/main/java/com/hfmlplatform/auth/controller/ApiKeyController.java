package com.hfmlplatform.auth.controller;

import com.hfmlplatform.auth.model.ApiKey;
import com.hfmlplatform.auth.model.User;
import com.hfmlplatform.auth.repository.UserRepository;
import com.hfmlplatform.auth.service.ApiKeyService;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/v1/auth/api-keys")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final UserRepository userRepository;

    public ApiKeyController(ApiKeyService apiKeyService, UserRepository userRepository) {
        this.apiKeyService = apiKeyService;
        this.userRepository = userRepository;
    }

    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> list() {
        User user = currentUser();
        if (user == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        List<Map<String, Object>> keys = apiKeyService.listApiKeys(user).stream()
                .map(k -> Map.<String, Object>of(
                        "id",         k.getId(),
                        "name",       k.getName(),
                        "created_at", k.getCreatedAt()
                ))
                .toList();

        return ResponseEntity.ok(keys);
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@RequestBody Map<String, String> body) {
        User user = currentUser();
        if (user == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        String keyName = body.get("name");

        if (keyName == null || keyName.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            String rawKey = apiKeyService.createApiKey(user, keyName);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("key", rawKey, "name", keyName));
        } catch (ApiKeyService.ApiKeyCapExceededException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        } catch (ApiKeyService.DuplicateKeyNameException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revoke(@PathVariable UUID id) {
        User user = currentUser();
        if (user == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        try {
            apiKeyService.revokeApiKey(user, id);
            return ResponseEntity.ok().build();
        } catch (ApiKeyService.ApiKeyNotFoundException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    private User currentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return null;
        if (!(auth.getPrincipal() instanceof Claims claims)) return null;
        return userRepository.findById(UUID.fromString(claims.getSubject())).orElse(null);
    }
}
