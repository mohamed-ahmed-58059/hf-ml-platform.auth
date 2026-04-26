package com.hfmlplatform.auth.controller;

import com.hfmlplatform.auth.dto.LoginResult;
import com.hfmlplatform.auth.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");

        if (email == null || email.isBlank() || password == null || password.length() < 8) {
            return ResponseEntity.badRequest().build();
        }

        if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            return ResponseEntity.badRequest().build();
        }

        try {
            authService.signup(email, password);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (AuthService.EmailAlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody Map<String, String> body,
                                      HttpServletRequest request,
                                      HttpServletResponse response) {
        String email = body.get("email");
        String password = body.get("password");

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        UUID existingSessionId = extractCookie(request, "sid")
                .map(v -> { try { return UUID.fromString(v); } catch (Exception e) { return null; } })
                .orElse(null);

        String ip = request.getHeader("X-Forwarded-For") != null
                ? request.getHeader("X-Forwarded-For").split(",")[0].trim()
                : request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        try {
            LoginResult result = authService.login(email, password, existingSessionId, ip, userAgent);
            setAuthCookies(response, result);
            return ResponseEntity.ok().build();
        } catch (AuthService.InvalidCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private void setAuthCookies(HttpServletResponse response, LoginResult result) {
        int sevenDaysSeconds = 7 * 24 * 60 * 60;
        int fifteenMinSeconds = 15 * 60;

        addCookie(response, "sid", result.sessionId().toString(), "/", sevenDaysSeconds);
        addCookie(response, "access_token", result.accessToken(), "/", fifteenMinSeconds);
        addCookie(response, "refresh_token", result.rawRefreshToken(), "/v1/auth/refresh", sevenDaysSeconds);
    }

    private void addCookie(HttpServletResponse response, String name, String value, String path, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(path);
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }

    private java.util.Optional<String> extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return java.util.Optional.empty();
        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
