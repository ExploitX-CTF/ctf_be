package com.ctf.platform.service;

import com.ctf.platform.dto.AuthDto;
import com.ctf.platform.model.User;
import com.ctf.platform.model.UserSession;
import com.ctf.platform.repository.UserRepository;
import com.ctf.platform.repository.UserSessionRepository;
import com.ctf.platform.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthDto.AuthResponse register(AuthDto.RegisterRequest request) {
        return register(request, "127.0.0.1", "Standard Browser");
    }

    public AuthDto.AuthResponse register(AuthDto.RegisterRequest request, String ipAddress, String userAgent) {
        String username = request.getUsername().trim();
        String email = request.getEmail().trim().toLowerCase();

        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already in use");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already in use");
        }

        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(request.getPassword()))
                .authProvider("LOCAL")
                .roles(Set.of("ROLE_USER"))
                .build();

        userRepository.save(user);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), request.getPassword())
        );

        String jwtToken = jwtTokenProvider.generateToken(authentication);
        String sessionToken = createSession(user, ipAddress, userAgent);

        return AuthDto.AuthResponse.builder()
                .token(jwtToken)
                .sessionToken(sessionToken)
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .build();
    }

    public AuthDto.AuthResponse login(AuthDto.LoginRequest request) {
        return login(request, "127.0.0.1", "Standard Browser");
    }

    public AuthDto.AuthResponse login(AuthDto.LoginRequest request, String ipAddress, String userAgent) {
        String identifier = request.getUsernameOrEmail().trim();

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(identifier, request.getPassword())
        );

        User user = userRepository.findByUsername(identifier)
                .or(() -> userRepository.findByEmail(identifier.toLowerCase()))
                .orElseThrow(() -> new RuntimeException("User not found"));

        String jwtToken = jwtTokenProvider.generateToken(authentication);
        String sessionToken = createSession(user, ipAddress, userAgent);

        return AuthDto.AuthResponse.builder()
                .token(jwtToken)
                .sessionToken(sessionToken)
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .avatarUrl(user.getAvatarUrl())
                .roles(user.getRoles())
                .build();
    }

    public AuthDto.AuthResponse loginWithGoogle(AuthDto.GoogleAuthRequest request, String ipAddress, String userAgent) {
        if (request.getEmail() == null || request.getEmail().isBlank()) {
            throw new RuntimeException("Google account must provide an email address");
        }

        String email = request.getEmail().trim().toLowerCase();
        String name = request.getName() != null && !request.getName().isBlank()
                ? request.getName().trim()
                : email.split("@")[0];

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            String baseUsername = name.replaceAll("[^a-zA-Z0-9_]", "").toLowerCase();
            if (baseUsername.length() < 3) baseUsername = "operator_" + baseUsername;
            String uniqueUsername = baseUsername;
            int counter = 1;
            while (userRepository.existsByUsername(uniqueUsername)) {
                uniqueUsername = baseUsername + counter++;
            }

            // Multi-layer encode a random secure password for OAuth accounts
            String randomSecret = UUID.randomUUID().toString() + UUID.randomUUID().toString();
            return User.builder()
                    .username(uniqueUsername)
                    .email(email)
                    .password(passwordEncoder.encode(randomSecret))
                    .googleId(request.getIdToken())
                    .avatarUrl(request.getAvatarUrl())
                    .authProvider("GOOGLE")
                    .roles(Set.of("ROLE_USER"))
                    .build();
        });

        if (request.getAvatarUrl() != null && !request.getAvatarUrl().isBlank()) {
            user.setAvatarUrl(request.getAvatarUrl());
        }
        if (request.getIdToken() != null && !request.getIdToken().isBlank()) {
            user.setGoogleId(request.getIdToken());
        }
        userRepository.save(user);

        // Build authentication token for JWT generation
        var userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                "",
                user.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        String jwtToken = jwtTokenProvider.generateToken(authentication);
        String sessionToken = createSession(user, ipAddress, userAgent);

        return AuthDto.AuthResponse.builder()
                .token(jwtToken)
                .sessionToken(sessionToken)
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .avatarUrl(user.getAvatarUrl())
                .roles(user.getRoles())
                .build();
    }

    public AuthDto.AuthResponse refreshSession(String sessionToken, String ipAddress, String userAgent) {
        if (sessionToken == null || sessionToken.isBlank()) {
            throw new RuntimeException("Session token is required");
        }

        UserSession session = userSessionRepository.findBySessionTokenAndRevokedFalse(sessionToken.trim())
                .orElseThrow(() -> new RuntimeException("Invalid or revoked session"));

        if (session.getExpiresAt() != null && session.getExpiresAt().isBefore(Instant.now())) {
            session.setRevoked(true);
            userSessionRepository.save(session);
            throw new RuntimeException("Session has expired. Please sign in again.");
        }

        User user = userRepository.findById(session.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found for session"));

        var userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                "",
                user.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        String newJwt = jwtTokenProvider.generateToken(authentication);

        return AuthDto.AuthResponse.builder()
                .token(newJwt)
                .sessionToken(sessionToken)
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .avatarUrl(user.getAvatarUrl())
                .roles(user.getRoles())
                .build();
    }

    public void logout(String sessionToken) {
        if (sessionToken != null && !sessionToken.isBlank()) {
            userSessionRepository.findBySessionTokenAndRevokedFalse(sessionToken.trim()).ifPresent(s -> {
                s.setRevoked(true);
                userSessionRepository.save(s);
            });
        }
    }

    public User getProfile(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    private String createSession(User user, String ipAddress, String userAgent) {
        String sessionToken = UUID.randomUUID().toString().replace("-", "") +
                UUID.randomUUID().toString().replace("-", "");

        UserSession session = UserSession.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .sessionToken(sessionToken)
                .ipAddress(ipAddress != null ? ipAddress : "Unknown")
                .userAgent(userAgent != null ? userAgent : "Unknown")
                .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        userSessionRepository.save(session);
        return sessionToken;
    }
}
