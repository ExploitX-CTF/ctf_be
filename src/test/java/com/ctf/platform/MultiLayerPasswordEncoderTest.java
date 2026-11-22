package com.ctf.platform;

import com.ctf.platform.security.MultiLayerPasswordEncoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

public class MultiLayerPasswordEncoderTest {

    private MultiLayerPasswordEncoder encoder;

    @BeforeEach
    public void setup() {
        encoder = new MultiLayerPasswordEncoder();
        ReflectionTestUtils.setField(encoder, "pepper", "TestPepperSecretKey2026CryptoLayer512");
    }

    @Test
    public void testEncodeAndMatchSuccess() {
        String rawPassword = "SuperSecretCTFPassword#2026";
        String encoded = encoder.encode(rawPassword);

        assertNotNull(encoded);
        assertTrue(encoded.startsWith("$2a$") || encoded.startsWith("$2b$"));
        assertTrue(encoder.matches(rawPassword, encoded));
    }

    @Test
    public void testMatchesFailsOnWrongPassword() {
        String rawPassword = "CorrectPassword123";
        String encoded = encoder.encode(rawPassword);

        assertFalse(encoder.matches("WrongPassword", encoded));
        assertFalse(encoder.matches("", encoded));
        assertFalse(encoder.matches(null, encoded));
    }

    @Test
    public void testSaltingProducesDifferentHashes() {
        String rawPassword = "IdenticalPassword!";
        String hash1 = encoder.encode(rawPassword);
        String hash2 = encoder.encode(rawPassword);

        assertNotEquals(hash1, hash2);
        assertTrue(encoder.matches(rawPassword, hash1));
        assertTrue(encoder.matches(rawPassword, hash2));
    }

    @Test
    public void testHmacLayerIsDeterministic() {
        String layerA = encoder.applyHmacPepperLayer("DeterministicTest");
        String layerB = encoder.applyHmacPepperLayer("DeterministicTest");
        assertEquals(layerA, layerB);
        assertEquals(64, layerA.length()); // SHA-256 hex is 64 chars (< 72-byte BCrypt max limit)
    }
}
