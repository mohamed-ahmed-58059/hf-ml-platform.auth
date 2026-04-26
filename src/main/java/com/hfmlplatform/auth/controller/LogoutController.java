package com.hfmlplatform.auth.controller;

import com.hfmlplatform.auth.repository.UserRepository;
import com.hfmlplatform.auth.service.LogoutService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/v1/auth")
public class LogoutController {

    private final LogoutService logoutService;
    private final UserRepository userRepository;

    public LogoutController(LogoutService logoutService, UserRepository userRepository) {
        this.logoutService = logoutService;
        this.userRepository = userRepository;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        extractCookie(request, "sid").ifPresent(sid -> {
            try {
                logoutService.logout(UUID.fromString(sid));
            } catch (Exception ignored) {}
        });
        clearCookies(response);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletResponse response) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof Claims claims)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        userRepository.findById(UUID.fromString(claims.getSubject()))
                .ifPresent(logoutService::logoutAll);
        clearCookies(response);
        return ResponseEntity.ok().build();
    }

    private void clearCookies(HttpServletResponse response) {
        for (String name : new String[]{"sid", "access_token"}) {
            Cookie cookie = new Cookie(name, "");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
        Cookie refreshCookie = new Cookie("refresh_token", "");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/v1/auth/refresh");
        refreshCookie.setMaxAge(0);
        response.addCookie(refreshCookie);
    }

    private Optional<String> extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return Optional.empty();
        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
