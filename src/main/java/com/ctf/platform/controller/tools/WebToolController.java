package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.WebEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/tools/web")
@RequiredArgsConstructor
public class WebToolController {

    private final WebEngineService webEngineService;

    @PostMapping("/jwt/analyze")
    public ResponseEntity<Map<String, Object>> analyzeJwt(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");
        String secret = body.getOrDefault("secret", "");
        return ResponseEntity.ok(webEngineService.analyzeJwt(token, secret));
    }

    @PostMapping("/jwt/forge")
    public ResponseEntity<Map<String, Object>> forgeJwt(@RequestBody Map<String, String> body) {
        String headerJson = body.getOrDefault("headerJson", "{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payloadJson = body.getOrDefault("payloadJson", "{}");
        String alg = body.getOrDefault("algorithm", "none");
        String secret = body.getOrDefault("secret", "");
        return ResponseEntity.ok(webEngineService.forgeJwt(headerJson, payloadJson, alg, secret));
    }

    @PostMapping("/jwt/crack")
    public ResponseEntity<Map<String, Object>> crackJwt(@RequestBody Map<String, Object> body) {
        String token = (String) body.getOrDefault("token", "");
        @SuppressWarnings("unchecked")
        List<String> customWordlist = (List<String>) body.get("customWordlist");
        return ResponseEntity.ok(webEngineService.crackJwtSecret(token, customWordlist));
    }

    @GetMapping("/payloads")
    public ResponseEntity<Map<String, Object>> getPayloads(
            @RequestParam(required = false, defaultValue = "all") String category,
            @RequestParam(required = false) String query) {
        return ResponseEntity.ok(webEngineService.getPayloadCatalog(category, query));
    }

    @PostMapping("/payloads/encode")
    public ResponseEntity<Map<String, Object>> encodePayload(@RequestBody Map<String, Object> body) {
        String raw = (String) body.getOrDefault("payload", "");
        String encoding = (String) body.getOrDefault("encoding", "raw");
        @SuppressWarnings("unchecked")
        Map<String, String> replacements = (Map<String, String>) body.get("replacements");
        return ResponseEntity.ok(webEngineService.encodePayload(raw, encoding, replacements));
    }

    @PostMapping("/headers/audit")
    public ResponseEntity<Map<String, Object>> auditHeaders(@RequestBody Map<String, String> body) {
        String rawHeaders = body.getOrDefault("headers", body.getOrDefault("raw", ""));
        return ResponseEntity.ok(webEngineService.auditHeaders(rawHeaders));
    }

    @PostMapping("/bypass/transform")
    public ResponseEntity<Map<String, Object>> transformFilterBypass(@RequestBody Map<String, Object> body) {
        String payload = (String) body.getOrDefault("payload", "");
        String type = (String) body.getOrDefault("type", "sqli");
        @SuppressWarnings("unchecked")
        List<String> techniques = (List<String>) body.get("techniques");
        return ResponseEntity.ok(webEngineService.transformFilterBypass(payload, type, techniques));
    }

    @PostMapping("/ua/parse")
    public ResponseEntity<Map<String, Object>> parseUserAgent(@RequestBody Map<String, String> body) {
        String ua = body.getOrDefault("userAgent", body.getOrDefault("ua", ""));
        return ResponseEntity.ok(webEngineService.parseUserAgent(ua));
    }

    @PostMapping("/url/decompose")
    public ResponseEntity<Map<String, Object>> decomposeUrl(@RequestBody Map<String, String> body) {
        String url = body.getOrDefault("url", body.getOrDefault("input", ""));
        return ResponseEntity.ok(webEngineService.decomposeUrl(url));
    }
}
