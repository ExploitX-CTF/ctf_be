package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.ReverseEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tools/reverse")
@RequiredArgsConstructor
public class ReverseToolController {

    private final ReverseEngineService reverseEngineService;

    @PostMapping("/cyclic/generate")
    public ResponseEntity<Map<String, Object>> generateCyclic(@RequestBody Map<String, Object> body) {
        int length = 200;
        if (body.get("length") != null) {
            try { length = Integer.parseInt(body.get("length").toString()); } catch (NumberFormatException ignored) {}
        }
        String pattern = reverseEngineService.generateCyclicPattern(length);
        return ResponseEntity.ok(Map.of("length", pattern.length(), "pattern", pattern));
    }

    @PostMapping("/cyclic/offset")
    public ResponseEntity<Map<String, Object>> findOffset(@RequestBody Map<String, String> body) {
        String needle = body.getOrDefault("needle", body.getOrDefault("input", ""));
        return ResponseEntity.ok(reverseEngineService.findCyclicOffset(needle));
    }

    @PostMapping("/endianness")
    public ResponseEntity<Map<String, Object>> convertEndianness(@RequestBody Map<String, Object> body) {
        String input = (String) body.getOrDefault("input", "");
        int bits = 32;
        if (body.get("bitWidth") != null) {
            try { bits = Integer.parseInt(body.get("bitWidth").toString()); } catch (NumberFormatException ignored) {}
        }
        return ResponseEntity.ok(reverseEngineService.convertEndianness(input, bits));
    }

    @GetMapping("/syscalls")
    public ResponseEntity<Map<String, Object>> getSyscalls(@RequestParam(required = false) String query) {
        return ResponseEntity.ok(reverseEngineService.getSyscalls(query));
    }

    @PostMapping("/pwntools")
    public ResponseEntity<Map<String, Object>> generatePwntools(@RequestBody Map<String, Object> body) {
        String binary = (String) body.getOrDefault("binary", "./chall");
        String host = (String) body.getOrDefault("host", "target.htb");
        Integer port = null;
        if (body.get("port") != null) {
            try { port = Integer.parseInt(body.get("port").toString()); } catch (NumberFormatException ignored) {}
        }
        String type = (String) body.getOrDefault("type", "bof");
        return ResponseEntity.ok(reverseEngineService.generatePwntoolsTemplate(binary, host, port, type));
    }

    @PostMapping("/brainfuck")
    public ResponseEntity<Map<String, Object>> interpretBrainfuck(@RequestBody Map<String, String> body) {
        String code = body.getOrDefault("code", body.getOrDefault("input", ""));
        String input = body.getOrDefault("inputData", "");
        return ResponseEntity.ok(reverseEngineService.interpretBrainfuck(code, input));
    }
}
