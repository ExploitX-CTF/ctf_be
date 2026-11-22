package com.ctf.platform.repository;

import com.ctf.platform.model.UserSession;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends MongoRepository<UserSession, String> {
    Optional<UserSession> findBySessionTokenAndRevokedFalse(String sessionToken);
    List<UserSession> findByUserIdAndRevokedFalse(String userId);
    void deleteBySessionToken(String sessionToken);
}
