package com.hfmlplatform.auth.controller;

import com.hfmlplatform.auth.dto.LoginResult;
import com.hfmlplatform.auth.service.RefreshService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Optional;

@RestController
@RequestMapping("/v1/auth")
public class RefreshController {

    private final RefreshService refreshService;

    public RefreshController(RefreshService refreshService) {
        this.refreshService = refreshService;
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refresh(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> rawToken = extractCookie(request, "refresh_token");
        if (rawToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            LoginResult result = refreshService.refresh(rawToken.get());

            int fifteenMinSeconds = 15 * 60;
            int sevenDaysSeconds  = 7 * 24 * 60 * 60;

            addCookie(response, "access_token",  result.accessToken(),      "/",                fifteenMinSeconds);
            addCookie(response, "refresh_token", result.rawRefreshToken(),  "/v1/auth/refresh", sevenDaysSeconds);

            return ResponseEntity.ok().build();
        } catch (RefreshService.TokenReuseDetectedException | RefreshService.InvalidTokenException e) {
            clearCookies(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
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

    private void clearCookies(HttpServletResponse response) {
        for (String name : new String[]{"sid", "access_token", "refresh_token"}) {
            Cookie cookie = new Cookie(name, "");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
    }

    private Optional<String> extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return Optional.empty();
        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
