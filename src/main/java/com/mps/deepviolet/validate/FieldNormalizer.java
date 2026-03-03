package com.mps.deepviolet.validate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Normalization logic for comparing DV API values against openssl values.
 * Handles differences in formatting, naming conventions, and representations.
 */
class FieldNormalizer {

    private static final Map<String, String> KEY_ALGORITHM_MAP = Map.of(
            "rsaencryption", "RSA",
            "id-ecpublickey", "EC",
            "ec", "EC",
            "rsa", "RSA",
            "ed25519", "Ed25519",
            "ed448", "Ed448"
    );

    private static final Map<String, String> CURVE_NAME_MAP = Map.of(
            "prime256v1", "secp256r1",
            "secp256r1", "secp256r1",
            "secp384r1", "secp384r1",
            "secp521r1", "secp521r1",
            "x25519", "X25519"
    );

    /**
     * Openssl date formats vary between LibreSSL and OpenSSL versions.
     * Examples: "Jan  5 12:00:00 2024 GMT", "2024-01-05T12:00:00Z"
     */
    private static final DateTimeFormatter[] OPENSSL_DATE_FORMATS = {
            DateTimeFormatter.ofPattern("MMM  d HH:mm:ss yyyy z", Locale.US),
            DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy z", Locale.US),
            DateTimeFormatter.ofPattern("MMM  d HH:mm:ss yyyy 'GMT'", Locale.US),
            DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy 'GMT'", Locale.US),
    };

    static String normalizeKeyAlgorithm(String value) {
        if (value == null) return "";
        String key = value.trim().toLowerCase(Locale.ROOT);
        return KEY_ALGORITHM_MAP.getOrDefault(key, value.trim());
    }

    static String normalizeSigningAlgorithm(String value) {
        if (value == null) return "";
        // Normalize to a canonical form: "<hash>with<keyalg>"
        // DV:     "SHA256withRSA", "SHA256withECDSA"
        // openssl: "sha256WithRSAEncryption", "ecdsa-with-SHA256"
        String v = value.trim().toLowerCase(Locale.ROOT).replaceAll("[\\s-]", "");

        // Handle openssl ECDSA format: "ecdsawithsha256" -> "sha256withecdsa"
        if (v.startsWith("ecdsawith")) {
            String hash = v.substring("ecdsawith".length());
            v = hash + "withecdsa";
        }

        // Strip RSA suffix
        v = v.replace("withrsaencryption", "withrsa");

        return v;
    }

    static String normalizeDN(String value) {
        if (value == null) return "";
        // Split on comma, trim each part, sort for order-independent comparison
        String[] parts = value.split(",");
        return Arrays.stream(parts)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .sorted()
                .collect(Collectors.joining(", "));
    }

    static String normalizeSerial(String value) {
        if (value == null) return "";
        // Remove colons, spaces, "0x" prefix; uppercase hex
        String hex = value.trim()
                .replaceAll("[:\\s]", "")
                .toUpperCase(Locale.ROOT);
        if (hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        // Strip leading zeros but keep at least one digit
        hex = hex.replaceFirst("^0+(?=.)", "");
        return hex;
    }

    static String normalizeFingerprint(String value) {
        if (value == null) return "";
        // Strip "SHA256:" prefix if present, remove colons/spaces, uppercase
        String fp = value.trim();
        if (fp.toUpperCase(Locale.ROOT).startsWith("SHA256:")) {
            fp = fp.substring(7);
        }
        // Also handle "SHA-256:" prefix
        if (fp.toUpperCase(Locale.ROOT).startsWith("SHA-256:")) {
            fp = fp.substring(8);
        }
        return fp.replaceAll("[:\\s]", "").toUpperCase(Locale.ROOT);
    }

    static String normalizeCurveName(String value) {
        if (value == null) return "";
        String key = value.trim().toLowerCase(Locale.ROOT);
        return CURVE_NAME_MAP.getOrDefault(key, value.trim());
    }

    static boolean compareDates(String dvDate, String opensslDate) {
        if (dvDate == null || opensslDate == null) return false;
        try {
            Instant dvInstant = parseDate(dvDate.trim());
            Instant osslInstant = parseDate(opensslDate.trim());
            if (dvInstant != null && osslInstant != null) {
                // Compare with 1-second tolerance
                return Math.abs(dvInstant.getEpochSecond() - osslInstant.getEpochSecond()) <= 1;
            }
        } catch (Exception e) {
            // Fall through to string comparison
        }
        // Fallback: normalized string comparison
        return dvDate.trim().equals(opensslDate.trim());
    }

    private static Instant parseDate(String dateStr) {
        // Try ISO format first (DV API often uses this)
        try {
            return Instant.parse(dateStr);
        } catch (DateTimeParseException ignored) {
        }

        // Try openssl date formats
        for (DateTimeFormatter fmt : OPENSSL_DATE_FORMATS) {
            try {
                LocalDateTime ldt = LocalDateTime.parse(dateStr, fmt);
                return ldt.toInstant(ZoneOffset.UTC);
            } catch (DateTimeParseException ignored) {
            }
        }

        // Try Java default date format
        try {
            java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat(
                    "EEE MMM dd HH:mm:ss zzz yyyy", Locale.US);
            return sdf.parse(dateStr).toInstant();
        } catch (Exception ignored) {
        }

        return null;
    }

    static boolean compareStringsNormalized(String dv, String openssl) {
        if (dv == null && openssl == null) return true;
        if (dv == null || openssl == null) return false;
        return dv.trim().equalsIgnoreCase(openssl.trim());
    }

    static boolean compareIntegers(int dv, int openssl) {
        return dv == openssl;
    }
}
