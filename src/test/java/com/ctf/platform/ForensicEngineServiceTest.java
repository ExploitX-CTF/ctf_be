package com.ctf.platform;

import com.ctf.platform.service.tools.ForensicEngineService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ForensicEngineServiceTest {

    private final ForensicEngineService service = new ForensicEngineService();

    @Test
    void testAnalyzeMagicBytesPngAndElf() {
        // PNG magic header test
        String pngHex = "89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52";
        Map<String, Object> pngRes = service.analyzeMagicBytes(pngHex);
        assertTrue((Boolean) pngRes.get("matched"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> pngMatches = (List<Map<String, Object>>) pngRes.get("matches");
        assertFalse(pngMatches.isEmpty());
        assertEquals("png", pngMatches.get(0).get("extension"));

        // ELF magic header test
        String elfHex = "7F 45 4C 46 02 01 01 00";
        Map<String, Object> elfRes = service.analyzeMagicBytes(elfHex);
        assertTrue((Boolean) elfRes.get("matched"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> elfMatches = (List<Map<String, Object>>) elfRes.get("matches");
        assertEquals("elf", elfMatches.get(0).get("extension"));

        // Corrupted PNG repair check
        Map<String, Object> corruptRes = service.analyzeMagicBytes("00 50 4E 47 0D 0A 1A 0A 49 48 44 52");
        @SuppressWarnings("unchecked")
        List<Map<String, String>> repairs = (List<Map<String, String>>) corruptRes.get("repairSuggestions");
        assertFalse(repairs.isEmpty());
    }

    @Test
    void testConvertTimestamp() {
        // Unix Epoch test (1700000000 = 2023-11-14T22:13:20Z)
        Map<String, Object> epochRes = service.convertTimestamp("1700000000");
        assertEquals("Unix Epoch (Seconds)", epochRes.get("detectedFormat"));
        assertEquals("2023-11-14T22:13:20Z", epochRes.get("utcIso"));
        assertNotNull(epochRes.get("windowsFileTime"));

        // Windows FileTime test (133444456000000000)
        Map<String, Object> winRes = service.convertTimestamp("133444456000000000");
        assertEquals("Windows 64-bit FileTime (NTFS)", winRes.get("detectedFormat"));
        assertNotNull(winRes.get("utcIso"));
    }

    @Test
    void testFixPngIhdrBruteForce() {
        // Standard 100x100 PNG IHDR calculation
        Map<String, Object> calcRes = service.fixPngIhdr(100L, 100L, null);
        assertNotNull(calcRes.get("calculatedCrcHex"));
        String correctCrc = (String) calcRes.get("calculatedCrcHex");

        // Simulate corrupted height: width=100, height=20, but target CRC belongs to height=100
        Map<String, Object> bruteRes = service.fixPngIhdr(100L, 20L, correctCrc);
        assertFalse((Boolean) bruteRes.get("crcValid"));
        assertTrue((Boolean) bruteRes.get("bruteForceSuccess"));
        assertEquals(100L, bruteRes.get("recoveredHeight"));
    }

    @Test
    void testGetMimeCatalogAndCredentials() {
        Map<String, Object> mimeRes = service.getMimeCatalog("png", "all");
        @SuppressWarnings("unchecked")
        List<?> list = (List<?>) mimeRes.get("signatures");
        assertFalse(list.isEmpty());

        Map<String, Object> credRes = service.getDefaultCredentials("raspberry", "all");
        @SuppressWarnings("unchecked")
        List<?> creds = (List<?>) credRes.get("credentials");
        assertFalse(creds.isEmpty());
    }

    @Test
    void testGenerateStegCommands() {
        Map<String, Object> res = service.generateStegCommands("stego_flag.png", "all", null, "p@ss");
        assertEquals("stego_flag.png", res.get("targetFile"));
        @SuppressWarnings("unchecked")
        Map<String, String> cmds = (Map<String, String>) res.get("commands");
        assertNotNull(cmds.get("Zsteg (PNG/BMP LSB planes detection)"));
        assertTrue(cmds.get("Steghide Extract (With passphrase)").contains("p@ss"));
    }
}
