package com.ctf.platform.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

public class AuthDto {

    @Data
    public static class LoginRequest {
        private String usernameOrEmail;
        private String password;
    }

    @Data
    public static class RegisterRequest {
        private String username;
        private String email;
        private String password;
    }

    @Data
    public static class GoogleAuthRequest {
        private String idToken;
        private String email;
        private String name;
        private String avatarUrl;
    }

    @Data
    public static class RefreshRequest {
        private String sessionToken;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthResponse {
        private String token; // JWT access token
        @Builder.Default
        private String type = "Bearer";
        private String sessionToken; // 30-day session token
        private String id;
        private String username;
        private String email;
        private String avatarUrl;
        private Object roles;

        public AuthResponse(String token, String sessionToken, String id, String username, String email, Object roles) {
            this.token = token;
            this.sessionToken = sessionToken;
            this.id = id;
            this.username = username;
            this.email = email;
            this.roles = roles;
            this.type = "Bearer";
        }

        public AuthResponse(String token, String id, String username, String email, Object roles) {
            this(token, null, id, username, email, roles);
        }
    }
}
