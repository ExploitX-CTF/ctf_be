package com.ctf.platform.controller;

import com.ctf.platform.dto.AuthDto;
import com.ctf.platform.model.User;
import com.ctf.platform.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthDto.RegisterRequest request, HttpServletRequest httpRequest) {
        try {
            String ip = extractClientIp(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");
            return ResponseEntity.ok(authService.register(request, ip, userAgent));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthDto.LoginRequest request, HttpServletRequest httpRequest) {
        try {
            String ip = extractClientIp(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");
            return ResponseEntity.ok(authService.login(request, ip, userAgent));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestBody AuthDto.GoogleAuthRequest request, HttpServletRequest httpRequest) {
        try {
            String ip = extractClientIp(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");
            return ResponseEntity.ok(authService.loginWithGoogle(request, ip, userAgent));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody AuthDto.RefreshRequest request, HttpServletRequest httpRequest) {
        try {
            String ip = extractClientIp(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");
            return ResponseEntity.ok(authService.refreshSession(request.getSessionToken(), ip, userAgent));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody(required = false) AuthDto.RefreshRequest request) {
        if (request != null && request.getSessionToken() != null) {
            authService.logout(request.getSessionToken());
        }
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getMe(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Unauthorized"));
        }
        User user = authService.getProfile(userDetails.getUsername());
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "avatarUrl", user.getAvatarUrl() != null ? user.getAvatarUrl() : "",
                "authProvider", user.getAuthProvider(),
                "roles", user.getRoles(),
                "score", user.getScore(),
                "solvesCount", user.getSolvesCount()
        ));
    }

    private String extractClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
