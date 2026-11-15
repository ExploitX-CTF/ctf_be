package com.ctf.platform;

import com.ctf.platform.service.tools.WebEngineService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class WebEngineServiceTest {

    private final WebEngineService service = new WebEngineService(new ObjectMapper());

    @Test
    void testForgeAndAnalyzeNoneAlg() {
        Map<String, Object> forged = service.forgeJwt(
                "{\"alg\":\"none\",\"typ\":\"JWT\"}",
                "{\"user\":\"guest\",\"role\":\"admin\",\"flag\":\"ctf{fake_flag}\"}",
                "none",
                ""
        );
        assertNull(forged.get("error"));
        String token = (String) forged.get("token");
        assertNotNull(token);
        assertTrue(token.endsWith("."));

        Map<String, Object> analysis = service.analyzeJwt(token, "");
        assertNull(analysis.get("error"));
        assertEquals("none", analysis.get("algorithm"));
        assertTrue((Boolean) analysis.get("signatureVerified"));

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) analysis.get("payload");
        assertEquals("admin", payload.get("role"));
    }

    @Test
    void testForgeAndCrackHmacSecret() {
        Map<String, Object> forged = service.forgeJwt(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                "{\"sub\":\"1337\",\"username\":\"admin\"}",
                "HS256",
                "secret"
        );
        String token = (String) forged.get("token");
        assertNotNull(token);

        Map<String, Object> analysis = service.analyzeJwt(token, "secret");
        assertTrue((Boolean) analysis.get("signatureVerified"));

        Map<String, Object> crackResult = service.crackJwtSecret(token, List.of("supersecret", "customkey"));
        assertTrue((Boolean) crackResult.get("found"));
        assertEquals("secret", crackResult.get("secret"));
    }

    @Test
    void testPayloadCatalogAndEncoding() {
        // Test category filter for SQLi
        Map<String, Object> sqliRes = service.getPayloadCatalog("sqli", null);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sqliList = (List<Map<String, Object>>) sqliRes.get("payloads");
        assertFalse(sqliList.isEmpty());
        assertTrue(sqliList.stream().allMatch(p -> "sqli".equals(p.get("category"))));

        // Test search filter
        Map<String, Object> searchRes = service.getPayloadCatalog("all", "passwd");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> searchList = (List<Map<String, Object>>) searchRes.get("payloads");
        assertFalse(searchList.isEmpty());

        // Test encoding with parameter replacements
        Map<String, Object> encRes = service.encodePayload(
                "; {{CMD}} ;",
                "url",
                Map.of("cmd", "cat /flag.txt")
        );
        assertEquals("; cat /flag.txt ;", encRes.get("raw"));
        assertEquals("%3B+cat+%2Fflag.txt+%3B", encRes.get("encoded"));
    }

    @Test
    void testAuditHeaders() {
        String insecureHeaders = """
                HTTP/1.1 200 OK
                Server: Apache/2.4.41 (Ubuntu)
                X-Powered-By: PHP/7.4.3
                Set-Cookie: session=12345
                """;
        Map<String, Object> res = service.auditHeaders(insecureHeaders);
        assertNotNull(res.get("checks"));
        assertTrue((Integer) res.get("score") < 80);
        assertTrue(List.of("C", "D", "F").contains(res.get("grade")));

        String secureHeaders = """
                HTTP/1.1 200 OK
                Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
                Content-Security-Policy: default-src 'self'
                X-Frame-Options: DENY
                X-Content-Type-Options: nosniff
                Referrer-Policy: strict-origin-when-cross-origin
                Permissions-Policy: geolocation=()
                Set-Cookie: session=secret; Secure; HttpOnly; SameSite=Strict
                """;
        Map<String, Object> secRes = service.auditHeaders(secureHeaders);
        assertEquals(100, secRes.get("score"));
        assertEquals("A+", secRes.get("grade"));
    }

    @Test
    void testTransformFilterBypass() {
        // Test SQLi transformations
        Map<String, Object> sqliRes = service.transformFilterBypass("' UNION SELECT 1, 'admin', 3-- -", "sqli", null);
        @SuppressWarnings("unchecked")
        Map<String, String> sqliVariants = (Map<String, String>) sqliRes.get("variants");
        assertNotNull(sqliVariants);
        assertTrue(sqliVariants.get("Comments as Whitespace (/**/)").contains("/**/UNION/**/"));
        assertTrue(sqliVariants.get("Tab Whitespace (%09)").contains("%09UNION%09"));
        assertTrue(sqliVariants.get("Hex Literal String Quotes (0x...)").contains("0x61646d696e"));

        // Test SSTI transformations
        Map<String, Object> sstiRes = service.transformFilterBypass("{{''.__class__.__mro__[1].__subclasses__()}}", "ssti", null);
        @SuppressWarnings("unchecked")
        Map<String, String> sstiVariants = (Map<String, String>) sstiRes.get("variants");
        assertNotNull(sstiVariants);
        assertTrue(sstiVariants.get("Bracket Key Lookup (['attr'])").contains("['__class__']"));
    }

    @Test
    void testParseUserAgent() {
        // Test SQLMap detector
        Map<String, Object> sqlmapRes = service.parseUserAgent("sqlmap/1.7.2#stable (https://sqlmap.org)");
        assertTrue((Boolean) sqlmapRes.get("isBot"));
        assertTrue(((String) sqlmapRes.get("botName")).contains("sqlmap"));

        // Test Desktop Chrome
        Map<String, Object> chromeRes = service.parseUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
        assertEquals("Google Chrome", chromeRes.get("browser"));
        assertEquals("Windows 10 / 11", chromeRes.get("os"));
        assertEquals("Blink", chromeRes.get("engine"));
        assertFalse((Boolean) chromeRes.get("isBot"));

        // Test CTF anomaly flag
        Map<String, Object> flagUa = service.parseUserAgent("CustomAdminClient/1.0 ctf{agent_flag_leak}");
        @SuppressWarnings("unchecked")
        List<String> alerts = (List<String>) flagUa.get("ctfAlerts");
        assertFalse(alerts.isEmpty());
        assertTrue(alerts.stream().anyMatch(a -> a.contains("CTF Flag")));
    }

    @Test
    void testDecomposeUrl() {
        String targetUrl = "https://target.htb:8443/api/v1/profile/view?redirect=https://evil.com&id=105&file=../../etc/passwd#section-flag";
        Map<String, Object> res = service.decomposeUrl(targetUrl);
        assertEquals("https", res.get("protocol"));
        assertEquals("target.htb", res.get("host"));
        assertEquals(8443, res.get("port"));
        assertEquals("/api/v1/profile/view", res.get("path"));
        assertEquals("section-flag", res.get("fragment"));

        @SuppressWarnings("unchecked")
        List<Map<String, String>> params = (List<Map<String, String>>) res.get("params");
        assertEquals(3, params.size());

        @SuppressWarnings("unchecked")
        List<Map<String, String>> alerts = (List<Map<String, String>>) res.get("securityAlerts");
        assertFalse(alerts.isEmpty());
        assertTrue(alerts.stream().anyMatch(a -> "Open Redirect".equals(a.get("type"))));
        assertTrue(alerts.stream().anyMatch(a -> "LFI / Traversal Candidate".equals(a.get("type"))));
        assertTrue(alerts.stream().anyMatch(a -> "SQLi / IDOR Candidate".equals(a.get("type"))));
    }
}
