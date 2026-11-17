package com.ctf.platform.service.tools;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;

@Slf4j
@Service
public class ForensicEngineService {

    // ── Magic Bytes Catalog ─────────────────────────────────────
    public record MagicSignature(String id, String name, String ext, String mime, String magicHex, int offset, String desc, String category) {}

    private static final List<MagicSignature> SIGNATURE_DATABASE = List.of(
            new MagicSignature("png", "Portable Network Graphics", "png", "image/png", "89504E470D0A1A0A", 0, "Standard PNG image format with IHDR chunk.", "Images"),
            new MagicSignature("jpg", "JPEG Image", "jpg", "image/jpeg", "FFD8FFE0", 0, "JPEG JFIF lossy image format.", "Images"),
            new MagicSignature("jpg-exif", "JPEG EXIF Image", "jpg", "image/jpeg", "FFD8FFE1", 0, "JPEG image containing EXIF metadata markers.", "Images"),
            new MagicSignature("gif87", "GIF 87a Image", "gif", "image/gif", "474946383761", 0, "Graphics Interchange Format 87a.", "Images"),
            new MagicSignature("gif89", "GIF 89a Image", "gif", "image/gif", "474946383961", 0, "Animated GIF 89a format.", "Images"),
            new MagicSignature("bmp", "Windows Bitmap", "bmp", "image/bmp", "424D", 0, "Standard Windows bitmap graphic.", "Images"),
            new MagicSignature("webp", "WebP Image", "webp", "image/webp", "52494646", 0, "RIFF container WebP image format.", "Images"),
            new MagicSignature("pdf", "PDF Document", "pdf", "application/pdf", "25504446", 0, "Adobe Portable Document Format (%PDF).", "Documents"),
            new MagicSignature("zip", "ZIP Archive", "zip", "application/zip", "504B0304", 0, "ZIP compressed archive (used by DOCX, XLSX, APK, JAR).", "Archives"),
            new MagicSignature("zip-empty", "Empty ZIP Archive", "zip", "application/zip", "504B0506", 0, "Empty ZIP or End of Central Directory record.", "Archives"),
            new MagicSignature("tar", "TAR Archive", "tar", "application/x-tar", "7573746172", 257, "POSIX tar archive format (ustar).", "Archives"),
            new MagicSignature("7z", "7-Zip Archive", "7z", "application/x-7z-compressed", "377ABCAF271C", 0, "7-Zip high-compression archive.", "Archives"),
            new MagicSignature("rar", "RAR Archive v4", "rar", "application/vnd.rar", "526172211A0700", 0, "Roshal Archive version 4.", "Archives"),
            new MagicSignature("rar5", "RAR Archive v5", "rar", "application/vnd.rar", "526172211A070100", 0, "Roshal Archive version 5.", "Archives"),
            new MagicSignature("gz", "GZIP Archive", "gz", "application/gzip", "1F8B08", 0, "GNU Gzip compression stream.", "Archives"),
            new MagicSignature("elf", "ELF Executable / Library", "elf", "application/x-executable", "7F454C46", 0, "Linux Executable and Linkable Format.", "Executables"),
            new MagicSignature("pe", "Windows PE Executable (MZ)", "exe", "application/x-dosexec", "4D5A", 0, "DOS / Windows Portable Executable header.", "Executables"),
            new MagicSignature("pcap", "PCAP Network Capture (LE)", "pcap", "application/vnd.tcpdump.pcap", "D4C3B2A1", 0, "Wireshark / tcpdump packet capture (Little-Endian).", "Network"),
            new MagicSignature("pcap-be", "PCAP Network Capture (BE)", "pcap", "application/vnd.tcpdump.pcap", "A1B2C3D4", 0, "Wireshark packet capture (Big-Endian).", "Network"),
            new MagicSignature("pcapng", "PCAP-NG Capture", "pcapng", "application/x-pcapng", "0A0D0D0A", 0, "Next Generation PCAP capture format.", "Network"),
            new MagicSignature("sqlite", "SQLite 3 Database", "sqlite", "application/x-sqlite3", "53514C69746520666F726D6174203300", 0, "SQLite 3 database format string.", "Database"),
            new MagicSignature("sqlite-wal", "SQLite Write-Ahead Log", "wal", "application/x-sqlite3-wal", "377F0682", 0, "SQLite 3 Write-Ahead Log.", "Database"),
            new MagicSignature("wav", "Waveform Audio (RIFF/WAVE)", "wav", "audio/wav", "52494646", 0, "RIFF container WAV audio.", "Audio"),
            new MagicSignature("mp3-id3", "MP3 Audio (ID3v2)", "mp3", "audio/mpeg", "494433", 0, "MP3 audio with ID3 metadata tag.", "Audio"),
            new MagicSignature("flac", "FLAC Audio", "flac", "audio/flac", "664C6143", 0, "Free Lossless Audio Codec.", "Audio")
    );

    // ── Default Credentials Database ─────────────────────────────
    private static final List<Map<String, String>> DEFAULT_CREDENTIALS = List.of(
            Map.of("service", "SSH / Linux", "product", "Raspberry Pi (Raspbian)", "username", "pi", "password", "raspberry", "port", "22", "notes", "Default prior to 2022 image updates."),
            Map.of("service", "SSH / Linux", "product", "Kali Linux (Pre-2020)", "username", "root", "password", "toor", "port", "22", "notes", "Legacy Kali default credentials."),
            Map.of("service", "SSH / Linux", "product", "Kali Linux (Modern)", "username", "kali", "password", "kali", "port", "22", "notes", "Modern Kali standard unprivileged account."),
            Map.of("service", "Database", "product", "MySQL / MariaDB", "username", "root", "password", "", "port", "3306", "notes", "Empty root password default on fresh dev installs."),
            Map.of("service", "Database", "product", "PostgreSQL", "username", "postgres", "password", "postgres", "port", "5432", "notes", "Standard default maintenance database credentials."),
            Map.of("service", "Database", "product", "MongoDB", "username", "admin", "password", "admin", "port", "27017", "notes", "Fresh installs frequently disable auth by default."),
            Map.of("service", "Database", "product", "Redis", "username", "", "password", "", "port", "6379", "notes", "Unauthenticated default bind on 0.0.0.0 enables direct RCE via ssh keys."),
            Map.of("service", "Router / Hardware", "product", "Cisco Routers / Switches", "username", "cisco", "password", "cisco", "port", "22 / 23", "notes", "Common enable secret: 'sanfran' or 'cisco'."),
            Map.of("service", "Router / Hardware", "product", "MikroTik RouterOS", "username", "admin", "password", "", "port", "80 / 8291", "notes", "Default admin account with blank password."),
            Map.of("service", "Router / Hardware", "product", "Ubiquiti UniFi / EdgeOS", "username", "ubnt", "password", "ubnt", "port", "22 / 443", "notes", "Default provisioning credentials."),
            Map.of("service", "Web Admin", "product", "Apache Tomcat Web App Manager", "username", "tomcat", "password", "s3cret", "port", "8080", "notes", "tomcat-users.xml default example; allows WAR deployment."),
            Map.of("service", "Web Admin", "product", "WordPress CMS", "username", "admin", "password", "admin", "port", "80 / 443", "notes", "Default installer suggestion."),
            Map.of("service", "Web Admin", "product", "Joomla CMS", "username", "admin", "password", "admin", "port", "80 / 443", "notes", "Default initial configuration account.")
    );

    /**
     * 1. Magic Bytes & File Signature Analyzer
     */
    public Map<String, Object> analyzeMagicBytes(String hexHeader) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (hexHeader == null || hexHeader.trim().isEmpty()) {
            result.put("error", "Hex header bytes string cannot be empty.");
            return result;
        }

        String cleanHex = hexHeader.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        result.put("inputHex", cleanHex);
        result.put("byteLength", cleanHex.length() / 2);

        List<Map<String, Object>> matches = new ArrayList<>();
        for (MagicSignature sig : SIGNATURE_DATABASE) {
            String targetSig = sig.magicHex().toUpperCase();
            int offsetHexChars = sig.offset() * 2;
            if (cleanHex.length() >= offsetHexChars + targetSig.length()) {
                String sub = cleanHex.substring(offsetHexChars, offsetHexChars + targetSig.length());
                if (sub.equals(targetSig)) {
                    Map<String, Object> match = new LinkedHashMap<>();
                    match.put("name", sig.name());
                    match.put("extension", sig.ext());
                    match.put("mimeType", sig.mime());
                    match.put("magicHex", sig.magicHex());
                    match.put("offset", sig.offset());
                    match.put("description", sig.desc());
                    match.put("category", sig.category());
                    matches.add(match);
                }
            }
        }

        result.put("matched", !matches.isEmpty());
        result.put("matches", matches);

        // Check for Common Corrupted Headers (CTF Fixes)
        List<Map<String, String>> repairSuggestions = new ArrayList<>();
        if (cleanHex.startsWith("00504E47") || cleanHex.startsWith("FF504E47") || cleanHex.contains("49484452")) {
            repairSuggestions.add(Map.of("type", "Corrupted PNG Header", "expectedHex", "89 50 4E 47 0D 0A 1A 0A", "fix", "Replace first 8 bytes with standard PNG magic signature."));
        }
        if (cleanHex.startsWith("00D8FF") || (cleanHex.contains("4A464946") && !cleanHex.startsWith("FFD8FF"))) {
            repairSuggestions.add(Map.of("type", "Corrupted JPEG Header", "expectedHex", "FF D8 FF E0", "fix", "Restore starting SOI marker FF D8 FF."));
        }
        if (cleanHex.contains("474946") && !cleanHex.startsWith("47494638")) {
            repairSuggestions.add(Map.of("type", "Corrupted GIF Header", "expectedHex", "47 49 46 38 39 61", "fix", "Restore standard GIF89a magic signature."));
        }
        result.put("repairSuggestions", repairSuggestions);

        return result;
    }

    /**
     * 2. Comprehensive Forensics Timestamp Converter
     */
    public Map<String, Object> convertTimestamp(String input) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (input == null || input.trim().isEmpty()) {
            result.put("error", "Timestamp input cannot be empty.");
            return result;
        }

        String raw = input.trim();
        Instant instant = null;
        String detectedFormat = "Unknown";

        try {
            // Check if numeric (epoch seconds, millis, micros, nanos, or Windows FileTime)
            if (raw.matches("^-?\\d+$")) {
                long num = Long.parseLong(raw);
                if (num > 116444736000000000L) {
                    // Windows Filetime (100-nanosecond intervals since Jan 1 1601 UTC)
                    detectedFormat = "Windows 64-bit FileTime (NTFS)";
                    long unixEpochMillis = (num - 116444736000000000L) / 10000;
                    instant = Instant.ofEpochMilli(unixEpochMillis);
                } else if (num > 1000000000000000L) {
                    // Nanoseconds / Microseconds
                    detectedFormat = "Unix Epoch (Microseconds)";
                    instant = Instant.ofEpochMilli(num / 1000);
                } else if (num > 100000000000L) {
                    // Milliseconds
                    detectedFormat = "Unix Epoch (Milliseconds)";
                    instant = Instant.ofEpochMilli(num);
                } else {
                    // Seconds
                    detectedFormat = "Unix Epoch (Seconds)";
                    instant = Instant.ofEpochSecond(num);
                }
            } else {
                // Try ISO 8601 parsing
                instant = Instant.parse(raw);
                detectedFormat = "ISO-8601 String";
            }
        } catch (Exception e) {
            result.put("error", "Could not parse timestamp: " + e.getMessage());
            return result;
        }

        if (instant != null) {
            long epochSec = instant.getEpochSecond();
            long epochMillis = instant.toEpochMilli();
            long windowsFileTime = (epochMillis * 10000) + 116444736000000000L;
            long chromeTime = (epochSec + 11644473600L) * 1000000L;

            DateTimeFormatter utcFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

            result.put("detectedFormat", detectedFormat);
            result.put("utcIso", instant.toString());
            result.put("utcFormatted", utcFormatter.format(instant));
            result.put("unixSeconds", epochSec);
            result.put("unixMillis", epochMillis);
            result.put("windowsFileTime", String.valueOf(windowsFileTime));
            result.put("chromeWebKitTime", String.valueOf(chromeTime));
        }

        return result;
    }

    /**
     * 3. PNG IHDR Chunk & CRC32 Validator / Brute-Forcer
     * Recomputes CRC32 or brute-forces dimensions if image height/width was tampered with.
     */
    public Map<String, Object> fixPngIhdr(Long width, Long height, String expectedCrcHex) {
        Map<String, Object> result = new LinkedHashMap<>();
        long w = (width != null) ? width : 100;
        long h = (height != null) ? height : 100;

        // IHDR Chunk format: 4 bytes 'IHDR' + 4 bytes Width + 4 bytes Height + 1 byte BitDepth + 1 byte ColorType + 1 byte Compression + 1 byte Filter + 1 byte Interlace
        byte[] ihdrHeader = new byte[] { 'I', 'H', 'D', 'R' };
        byte bitDepth = 8;
        byte colorType = 6; // RGBA
        byte compression = 0;
        byte filter = 0;
        byte interlace = 0;

        ByteBuffer buffer = ByteBuffer.allocate(17);
        buffer.put(ihdrHeader);
        buffer.putInt((int) w);
        buffer.putInt((int) h);
        buffer.put(bitDepth);
        buffer.put(colorType);
        buffer.put(compression);
        buffer.put(filter);
        buffer.put(interlace);

        CRC32 crc32 = new CRC32();
        crc32.update(buffer.array());
        long calculatedCrc = crc32.getValue();
        String calcHex = String.format("%08X", calculatedCrc);

        result.put("currentWidth", w);
        result.put("currentHeight", h);
        result.put("calculatedCrcHex", calcHex);
        result.put("calculatedCrcDecimal", calculatedCrc);

        if (expectedCrcHex != null && !expectedCrcHex.trim().isEmpty()) {
            String cleanExpected = expectedCrcHex.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
            result.put("expectedCrcHex", cleanExpected);
            boolean matches = calcHex.equalsIgnoreCase(cleanExpected);
            result.put("crcValid", matches);

            if (!matches) {
                // Brute-force dimensions (CTF solver up to 3000x3000)
                long targetCrc = Long.parseLong(cleanExpected, 16);
                boolean found = false;
                long recoveredW = -1;
                long recoveredH = -1;

                // First attempt: hold width constant, vary height
                byte[] testBuf = new byte[17];
                System.arraycopy(ihdrHeader, 0, testBuf, 0, 4);
                testBuf[4] = (byte) ((w >> 24) & 0xFF);
                testBuf[5] = (byte) ((w >> 16) & 0xFF);
                testBuf[6] = (byte) ((w >> 8) & 0xFF);
                testBuf[7] = (byte) (w & 0xFF);
                testBuf[12] = bitDepth;
                testBuf[13] = colorType;
                testBuf[14] = compression;
                testBuf[15] = filter;
                testBuf[16] = interlace;

                for (int testH = 1; testH <= 4000; testH++) {
                    testBuf[8] = (byte) ((testH >> 24) & 0xFF);
                    testBuf[9] = (byte) ((testH >> 16) & 0xFF);
                    testBuf[10] = (byte) ((testH >> 8) & 0xFF);
                    testBuf[11] = (byte) (testH & 0xFF);

                    crc32.reset();
                    crc32.update(testBuf);
                    if (crc32.getValue() == targetCrc) {
                        found = true;
                        recoveredW = w;
                        recoveredH = testH;
                        break;
                    }
                }

                if (found) {
                    result.put("bruteForceSuccess", true);
                    result.put("recoveredWidth", recoveredW);
                    result.put("recoveredHeight", recoveredH);
                    result.put("explanation", "Recovered hidden image dimensions! Altering the height reveals the full CTF flag at the bottom of the PNG.");
                } else {
                    result.put("bruteForceSuccess", false);
                    result.put("explanation", "Could not match CRC32 by varying height up to 4000px. The colorType/bitDepth or width may also differ.");
                }
            }
        }

        return result;
    }

    /**
     * 4. Searchable MIME Type & Signatures Catalog
     */
    public Map<String, Object> getMimeCatalog(String query, String category) {
        List<MagicSignature> filtered = SIGNATURE_DATABASE.stream()
                .filter(s -> {
                    if (category != null && !category.equalsIgnoreCase("all") && !category.equalsIgnoreCase(s.category())) {
                        return false;
                    }
                    if (query != null && !query.trim().isEmpty()) {
                        String q = query.toLowerCase().trim();
                        return s.name().toLowerCase().contains(q) ||
                                s.ext().toLowerCase().contains(q) ||
                                s.mime().toLowerCase().contains(q) ||
                                s.magicHex().toLowerCase().contains(q);
                    }
                    return true;
                })
                .toList();

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("total", filtered.size());
        res.put("signatures", filtered);
        return res;
    }

    /**
     * 5. Default Credentials Database
     */
    public Map<String, Object> getDefaultCredentials(String query, String category) {
        List<Map<String, String>> filtered = DEFAULT_CREDENTIALS.stream()
                .filter(c -> {
                    if (category != null && !category.equalsIgnoreCase("all") && !category.equalsIgnoreCase(c.get("service"))) {
                        return false;
                    }
                    if (query != null && !query.trim().isEmpty()) {
                        String q = query.toLowerCase().trim();
                        return c.get("product").toLowerCase().contains(q) ||
                                c.get("service").toLowerCase().contains(q) ||
                                c.get("username").toLowerCase().contains(q) ||
                                c.get("notes").toLowerCase().contains(q);
                    }
                    return true;
                })
                .toList();

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("total", filtered.size());
        res.put("credentials", filtered);
        return res;
    }

    /**
     * 6. Steganography CLI Command Generator
     */
    public Map<String, Object> generateStegCommands(String filename, String toolType, String wordlist, String pass) {
        String file = (filename != null && !filename.trim().isEmpty()) ? filename.trim() : "evidence.png";
        String wl = (wordlist != null && !wordlist.trim().isEmpty()) ? wordlist.trim() : "/usr/share/wordlists/rockyou.txt";
        String p = (pass != null) ? pass.trim() : "";

        Map<String, String> commands = new LinkedHashMap<>();
        commands.put("Strings (Readable Text & Flag extraction)", "strings -n 8 " + file + " | grep -Ei 'flag|ctf|key|secret'");
        commands.put("Binwalk (Embedded file extraction)", "binwalk -e --dd='.*' " + file);
        commands.put("Foremost (Automatic file carving)", "foremost -i " + file + " -o ./carved_output");
        commands.put("ExifTool (All metadata tags)", "exiftool -a -u -g1 " + file);
        commands.put("Zsteg (PNG/BMP LSB planes detection)", "zsteg -a " + file);
        commands.put("Steghide Extract (With passphrase)", "steghide extract -sf " + file + (p.isEmpty() ? " -p ''" : " -p '" + p + "'"));
        commands.put("Stegcracker (Brute-force passphrase)", "stegcracker " + file + " " + wl);
        commands.put("PNGcheck (PNG integrity check)", "pngcheck -vvt " + file);

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("targetFile", file);
        res.put("commands", commands);
        return res;
    }
}
