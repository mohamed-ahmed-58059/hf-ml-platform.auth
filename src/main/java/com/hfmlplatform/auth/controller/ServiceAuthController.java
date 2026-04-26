package com.hfmlplatform.auth.controller;

import com.hfmlplatform.auth.service.ServiceAuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
public class ServiceAuthController {

    private final ServiceAuthService serviceAuthService;

    public ServiceAuthController(ServiceAuthService serviceAuthService) {
        this.serviceAuthService = serviceAuthService;
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(@RequestBody Map<String, String> body) {
        String clientId     = body.get("client_id");
        String clientSecret = body.get("client_secret");

        if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            String accessToken = serviceAuthService.issueToken(clientId, clientSecret);
            return ResponseEntity.ok(Map.of(
                    "access_token", accessToken,
                    "expires_in", 900
            ));
        } catch (ServiceAuthService.InvalidClientException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
