package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.ForensicEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tools/forensics")
@RequiredArgsConstructor
public class ForensicToolController {

    private final ForensicEngineService forensicEngineService;

    @PostMapping("/magic")
    public ResponseEntity<Map<String, Object>> analyzeMagicBytes(@RequestBody Map<String, String> body) {
        String hex = body.getOrDefault("hex", body.getOrDefault("input", ""));
        return ResponseEntity.ok(forensicEngineService.analyzeMagicBytes(hex));
    }

    @PostMapping("/timestamp")
    public ResponseEntity<Map<String, Object>> convertTimestamp(@RequestBody Map<String, String> body) {
        String ts = body.getOrDefault("timestamp", body.getOrDefault("input", ""));
        return ResponseEntity.ok(forensicEngineService.convertTimestamp(ts));
    }

    @PostMapping("/png/ihdr")
    public ResponseEntity<Map<String, Object>> fixPngIhdr(@RequestBody Map<String, Object> body) {
        Long width = null;
        Long height = null;
        if (body.get("width") != null) {
            try { width = Long.parseLong(body.get("width").toString()); } catch (NumberFormatException ignored) {}
        }
        if (body.get("height") != null) {
            try { height = Long.parseLong(body.get("height").toString()); } catch (NumberFormatException ignored) {}
        }
        String expectedCrc = (String) body.getOrDefault("expectedCrc", body.getOrDefault("crc", ""));
        return ResponseEntity.ok(forensicEngineService.fixPngIhdr(width, height, expectedCrc));
    }

    @GetMapping("/signatures")
    public ResponseEntity<Map<String, Object>> getMimeSignatures(
            @RequestParam(required = false) String query,
            @RequestParam(required = false, defaultValue = "all") String category) {
        return ResponseEntity.ok(forensicEngineService.getMimeCatalog(query, category));
    }

    @GetMapping("/credentials")
    public ResponseEntity<Map<String, Object>> getDefaultCredentials(
            @RequestParam(required = false) String query,
            @RequestParam(required = false, defaultValue = "all") String category) {
        return ResponseEntity.ok(forensicEngineService.getDefaultCredentials(query, category));
    }

    @PostMapping("/steg/commands")
    public ResponseEntity<Map<String, Object>> generateStegCommands(@RequestBody Map<String, String> body) {
        String file = body.getOrDefault("filename", "evidence.png");
        String toolType = body.getOrDefault("toolType", "all");
        String wordlist = body.getOrDefault("wordlist", "/usr/share/wordlists/rockyou.txt");
        String pass = body.getOrDefault("passphrase", "");
        return ResponseEntity.ok(forensicEngineService.generateStegCommands(file, toolType, wordlist, pass));
    }
}
