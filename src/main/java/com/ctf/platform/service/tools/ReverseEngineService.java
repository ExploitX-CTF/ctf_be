package com.ctf.platform.service.tools;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Service
public class ReverseEngineService {

    // ── 1. De Bruijn Cyclic Pattern Generator & Offset Finder ────────
    private static final String CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHARSET_DIGITS = "0123456789";

    public String generateCyclicPattern(int length) {
        int max = Math.min(Math.max(length, 4), 20000);
        StringBuilder sb = new StringBuilder(max);
        for (int i = 0; i < CHARSET_UPPER.length(); i++) {
            for (int j = 0; j < CHARSET_LOWER.length(); j++) {
                for (int k = 0; k < CHARSET_DIGITS.length(); k++) {
                    sb.append(CHARSET_UPPER.charAt(i))
                      .append(CHARSET_LOWER.charAt(j))
                      .append(CHARSET_DIGITS.charAt(k));
                    if (sb.length() >= max) {
                        return sb.substring(0, max);
                    }
                }
            }
        }
        return sb.substring(0, Math.min(sb.length(), max));
    }

    public Map<String, Object> findCyclicOffset(String needle) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (needle == null || needle.trim().isEmpty()) {
            result.put("error", "Search value cannot be empty.");
            return result;
        }

        String search = needle.trim();
        // If hex value like 0x41306141 or 41306141, decode to ascii bytes in little-endian
        String asciiSearch = search;
        if (search.startsWith("0x") || search.startsWith("0X") || search.matches("^[0-9A-Fa-f]{8}$") || search.matches("^[0-9A-Fa-f]{16}$")) {
            String clean = search.replaceAll("^0[xX]", "");
            try {
                // Parse hex bytes and reverse for Little-Endian EIP/RIP
                byte[] bytes = new byte[clean.length() / 2];
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
                }
                // Reverse little-endian
                StringBuilder le = new StringBuilder();
                for (int i = bytes.length - 1; i >= 0; i--) {
                    le.append((char) bytes[i]);
                }
                asciiSearch = le.toString();
            } catch (Exception ignored) {}
        }

        String pattern = generateCyclicPattern(10000);
        int offset = pattern.indexOf(asciiSearch);
        if (offset == -1 && !asciiSearch.equals(search)) {
            // Try direct needle
            offset = pattern.indexOf(search);
        }

        result.put("needle", needle);
        result.put("asciiDecoded", asciiSearch);
        result.put("found", offset != -1);
        result.put("offset", offset);
        if (offset != -1) {
            result.put("explanation", "Match found at offset " + offset + " bytes! This is the exact buffer size needed to reach the saved instruction pointer (EIP/RIP).");
        } else {
            result.put("explanation", "Value not found in standard 10,000-byte pattern space.");
        }
        return result;
    }

    // ── 2. Endianness Converter ──────────────────────────────────────
    public Map<String, Object> convertEndianness(String input, int bitWidth) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (input == null || input.trim().isEmpty()) {
            result.put("error", "Input value cannot be empty.");
            return result;
        }

        String raw = input.trim();
        int bits = (bitWidth == 16 || bitWidth == 64) ? bitWidth : 32;
        int byteCount = bits / 8;

        BigInteger val;
        try {
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                val = new BigInteger(raw.substring(2), 16);
            } else if (raw.matches("^[0-9A-Fa-f]+$") && raw.length() > 6) {
                val = new BigInteger(raw, 16);
            } else {
                val = new BigInteger(raw, 10);
            }
        } catch (Exception e) {
            result.put("error", "Invalid numeric or hex input: " + e.getMessage());
            return result;
        }

        // Format Big Endian hex
        String beHex = String.format("%0" + (byteCount * 2) + "X", val);
        if (beHex.length() > byteCount * 2) {
            beHex = beHex.substring(beHex.length() - byteCount * 2);
        }

        // Form Little Endian
        StringBuilder leHex = new StringBuilder();
        StringBuilder cEscape = new StringBuilder();
        StringBuilder pythonPack = new StringBuilder();
        for (int i = beHex.length() - 2; i >= 0; i -= 2) {
            String bytePair = beHex.substring(i, i + 2);
            leHex.append(bytePair);
            cEscape.append("\\x").append(bytePair.toLowerCase());
        }

        result.put("input", input);
        result.put("bitWidth", bits);
        result.put("decimal", val.toString());
        result.put("bigEndianHex", "0x" + beHex);
        result.put("littleEndianHex", "0x" + leHex);
        result.put("escapedLittleEndian", cEscape.toString());
        result.put("pwntoolsPack", (bits == 64 ? "p64(" : bits == 32 ? "p32(" : "p16(") + "0x" + beHex + ")");
        return result;
    }

    // ── 3. Linux Syscall Reference Table ─────────────────────────────
    public record SyscallDef(int nr, String name, String rax, String rdi, String rsi, String rdx, String r10, String r8, String r9, String desc) {}

    private static final List<SyscallDef> SYSCALLS_X64 = List.of(
            new SyscallDef(0, "sys_read", "0x00", "unsigned int fd", "char *buf", "size_t count", "-", "-", "-", "Read from file descriptor"),
            new SyscallDef(1, "sys_write", "0x01", "unsigned int fd", "const char *buf", "size_t count", "-", "-", "-", "Write to file descriptor"),
            new SyscallDef(2, "sys_open", "0x02", "const char *filename", "int flags", "umode_t mode", "-", "-", "-", "Open file"),
            new SyscallDef(3, "sys_close", "0x03", "unsigned int fd", "-", "-", "-", "-", "-", "Close file descriptor"),
            new SyscallDef(9, "sys_mmap", "0x09", "unsigned long addr", "unsigned long len", "unsigned long prot", "unsigned long flags", "unsigned long fd", "unsigned long off", "Map memory pages (RWX allocation)"),
            new SyscallDef(10, "sys_mprotect", "0x0a", "unsigned long start", "size_t len", "unsigned long prot", "PROT_READ|PROT_WRITE|PROT_EXEC", "-", "-", "Change memory permissions to executable (Shellcode prep)"),
            new SyscallDef(33, "sys_dup2", "0x21", "unsigned int oldfd", "unsigned int newfd", "-", "-", "-", "-", "Duplicate file descriptor (Socket I/O redirection)"),
            new SyscallDef(57, "sys_fork", "0x39", "-", "-", "-", "-", "-", "-", "Fork current process"),
            new SyscallDef(59, "sys_execve", "0x3b", "const char *filename", "const char *const *argv", "const char *const *envp", "-", "-", "-", "Execute program (/bin/sh execve payload)"),
            new SyscallDef(60, "sys_exit", "0x3c", "int error_code", "-", "-", "-", "-", "-", "Terminate calling process cleanly")
    );

    public Map<String, Object> getSyscalls(String query) {
        List<SyscallDef> filtered = SYSCALLS_X64.stream()
                .filter(s -> {
                    if (query != null && !query.trim().isEmpty()) {
                        String q = query.toLowerCase().trim();
                        return s.name().toLowerCase().contains(q) ||
                                String.valueOf(s.nr()).equals(q) ||
                                s.desc().toLowerCase().contains(q) ||
                                s.rdi().toLowerCase().contains(q);
                    }
                    return true;
                })
                .toList();

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("total", filtered.size());
        res.put("syscalls", filtered);
        return res;
    }

    // ── 4. Pwntools Python Script Template Generator ─────────────────
    public Map<String, Object> generatePwntoolsTemplate(String binary, String host, Integer port, String exploitType) {
        String bin = (binary != null && !binary.trim().isEmpty()) ? binary.trim() : "./chall";
        String rHost = (host != null && !host.trim().isEmpty()) ? host.trim() : "target.htb";
        int rPort = (port != null && port > 0) ? port : 1337;
        String type = (exploitType != null) ? exploitType.toLowerCase() : "bof";

        StringBuilder py = new StringBuilder();
        py.append("#!/usr/bin/env python3\n");
        py.append("from pwn import *\n\n");
        py.append("# ── Architecture Configuration ──\n");
        py.append("context.binary = exe = ELF('").append(bin).append("', checksec=True)\n");
        py.append("context.log_level = 'debug'\n\n");
        py.append("def start():\n");
        py.append("    if args.REMOTE:\n");
        py.append("        return remote('").append(rHost).append("', ").append(rPort).append(")\n");
        py.append("    else:\n");
        py.append("        return process([exe.path])\n\n");
        py.append("io = start()\n\n");

        switch (type) {
            case "ret2win" -> {
                py.append("# ── Ret2win Exploit ──\n");
                py.append("offset = 72 # Replace with cyclic offset\n");
                py.append("win_addr = exe.symbols['win']\n");
                py.append("ret_gadget = 0x40101a # 'ret' for 16-byte stack alignment if glibc >= 2.27\n\n");
                py.append("payload = flat([\n");
                py.append("    b'A' * offset,\n");
                py.append("    ret_gadget,\n");
                py.append("    win_addr\n");
                py.append("])\n");
            }
            case "shellcode" -> {
                py.append("# ── Stack Shellcode Injection ──\n");
                py.append("offset = 72\n");
                py.append("shellcode = asm(shellcraft.sh())\n");
                py.append("io.recvuntil(b'Buffer is at: ')\n");
                py.append("buf_addr = int(io.recvline().strip(), 16)\n\n");
                py.append("payload = flat([\n");
                py.append("    shellcode,\n");
                py.append("    b'\\x90' * (offset - len(shellcode)),\n");
                py.append("    buf_addr\n");
                py.append("])\n");
            }
            default -> {
                py.append("# ── Standard Buffer Overflow / ROP ──\n");
                py.append("offset = 72 # Replace with cyclic offset\n");
                py.append("rop = ROP(exe)\n");
                py.append("# rop.raw(...) # Construct ROP chain\n\n");
                py.append("payload = flat([\n");
                py.append("    b'A' * offset,\n");
                py.append("    # rop.chain()\n");
                py.append("])\n");
            }
        }

        py.append("\nio.sendline(payload)\n");
        py.append("io.interactive()\n");

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("script", py.toString());
        res.put("binary", bin);
        res.put("remoteTarget", rHost + ":" + rPort);
        res.put("type", type);
        return res;
    }

    // ── 5. Brainfuck Virtual Machine Interpreter ─────────────────────
    public Map<String, Object> interpretBrainfuck(String code, String input) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (code == null) code = "";

        char[] program = code.replaceAll("[^><+\\-.,\\[\\]]", "").toCharArray();
        char[] inChars = (input != null) ? input.toCharArray() : new char[0];
        int inPtr = 0;

        byte[] memory = new byte[30000];
        int ptr = 0;
        StringBuilder output = new StringBuilder();
        int maxOps = 1000000;
        int ops = 0;

        // Precompute bracket matching
        Map<Integer, Integer> bracketMap = new HashMap<>();
        Deque<Integer> stack = new ArrayDeque<>();
        for (int i = 0; i < program.length; i++) {
            if (program[i] == '[') {
                stack.push(i);
            } else if (program[i] == ']') {
                if (stack.isEmpty()) {
                    result.put("error", "Unmatched closing bracket ']' at instruction " + i);
                    return result;
                }
                int open = stack.pop();
                bracketMap.put(open, i);
                bracketMap.put(i, open);
            }
        }
        if (!stack.isEmpty()) {
            result.put("error", "Unmatched opening bracket '[' at instruction " + stack.pop());
            return result;
        }

        int pc = 0;
        while (pc < program.length && ops < maxOps) {
            ops++;
            char cmd = program[pc];
            switch (cmd) {
                case '>' -> ptr = (ptr + 1) % 30000;
                case '<' -> ptr = (ptr - 1 + 30000) % 30000;
                case '+' -> memory[ptr]++;
                case '-' -> memory[ptr]--;
                case '.' -> output.append((char) (memory[ptr] & 0xFF));
                case ',' -> memory[ptr] = (byte) (inPtr < inChars.length ? inChars[inPtr++] : 0);
                case '[' -> {
                    if (memory[ptr] == 0) {
                        pc = bracketMap.get(pc);
                    }
                }
                case ']' -> {
                    if (memory[ptr] != 0) {
                        pc = bracketMap.get(pc);
                    }
                }
            }
            pc++;
        }

        result.put("output", output.toString());
        result.put("opsCount", ops);
        result.put("memoryPointer", ptr);
        result.put("timeout", ops >= maxOps);
        return result;
    }
}
