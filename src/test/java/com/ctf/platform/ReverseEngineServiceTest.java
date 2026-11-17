package com.ctf.platform;

import com.ctf.platform.service.tools.ReverseEngineService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ReverseEngineServiceTest {

    private final ReverseEngineService service = new ReverseEngineService();

    @Test
    void testCyclicPatternAndOffset() {
        String pattern = service.generateCyclicPattern(200);
        assertEquals(200, pattern.length());
        assertTrue(pattern.startsWith("Aa0Aa1Aa2"));

        // Match first needle 'Aa0'
        Map<String, Object> offsetRes = service.findCyclicOffset("Aa0");
        assertTrue((Boolean) offsetRes.get("found"));
        assertEquals(0, offsetRes.get("offset"));

        // Match hex needle (e.g. ASCII 'Aa1' in hex Little-Endian)
        Map<String, Object> offset2 = service.findCyclicOffset("Aa1");
        assertTrue((Boolean) offset2.get("found"));
        assertEquals(3, offset2.get("offset"));
    }

    @Test
    void testEndiannessConverter() {
        // 0xdeadbeef in 32-bit: Little Endian should be 0xEFBEADDE and \xef\xbe\xad\xde
        Map<String, Object> res = service.convertEndianness("0xdeadbeef", 32);
        assertEquals("0xDEADBEEF", res.get("bigEndianHex"));
        assertEquals("0xEFBEADDE", res.get("littleEndianHex"));
        assertEquals("\\xef\\xbe\\xad\\xde", res.get("escapedLittleEndian"));
        assertEquals("p32(0xDEADBEEF)", res.get("pwntoolsPack"));
    }

    @Test
    void testSyscallsQuery() {
        Map<String, Object> res = service.getSyscalls("execve");
        @SuppressWarnings("unchecked")
        List<?> list = (List<?>) res.get("syscalls");
        assertFalse(list.isEmpty());

        Map<String, Object> allRes = service.getSyscalls(null);
        assertTrue((Integer) allRes.get("total") >= 10);
    }

    @Test
    void testPwntoolsTemplate() {
        Map<String, Object> res = service.generatePwntoolsTemplate("./vuln", "ctf.box", 9999, "ret2win");
        String script = (String) res.get("script");
        assertNotNull(script);
        assertTrue(script.contains("ELF('./vuln'"));
        assertTrue(script.contains("remote('ctf.box', 9999)"));
        assertTrue(script.contains("win_addr"));
    }

    @Test
    void testBrainfuckInterpreter() {
        // Brainfuck program that outputs 'A' (ASCII 65): ++++++++++[>+++++++<-]>-----.
        String bf = "++++++++++[>+++++++<-]>-----.";
        Map<String, Object> res = service.interpretBrainfuck(bf, "");
        assertEquals("A", res.get("output"));
        assertNull(res.get("error"));
    }
}
