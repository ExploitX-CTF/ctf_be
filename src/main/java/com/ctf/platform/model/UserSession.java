package com.ctf.platform.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "user_sessions")
public class UserSession {

    @Id
    private String id;

    @Indexed
    private String userId;

    private String username;

    @Indexed(unique = true)
    private String sessionToken;

    private String ipAddress;

    private String userAgent;

    private Instant expiresAt;

    @CreatedDate
    private Instant createdAt;

    @Builder.Default
    private boolean revoked = false;
}
