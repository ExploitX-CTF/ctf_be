package com.ctf.platform.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Multi-layer password encoder combining:
 * Layer 1: Server-side cryptographic pepper via HMAC-SHA256 (64-byte hex string within BCrypt's 72-byte max)
 * Layer 2: Adaptive BCrypt with work factor 12 (salted, key-stretched hashing)
 */
@Component
public class MultiLayerPasswordEncoder implements PasswordEncoder {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    @Value("${app.security.pepper:ExploitXMultiLayerSecurityPepperSecret2026KeyCryptoHMAC256}")
    private String pepper;

    public String applyHmacPepperLayer(CharSequence rawPassword) {
        if (rawPassword == null) {
            rawPassword = "";
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] bytes = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes); // 64 chars <= 72 bytes BCrypt limit
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute HMAC password layer", e);
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        String peppered = applyHmacPepperLayer(rawPassword);
        return bcrypt.encode(peppered);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null || encodedPassword.isEmpty()) {
            return false;
        }
        String peppered = applyHmacPepperLayer(rawPassword);
        return bcrypt.matches(peppered, encodedPassword);
    }
}
