package com.hfmlplatform.auth.controller;

import com.hfmlplatform.auth.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
public class PublicKeyController {

    private final TokenService tokenService;

    public PublicKeyController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> publicKey() {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'})
                        .encodeToString(tokenService.getPublicKey().getEncoded())
                + "\n-----END PUBLIC KEY-----";
        return ResponseEntity.ok(Map.of("public_key", pem));
    }
}
