package com.mps.deepviolet.api.fingerprint;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class TlsServerFingerprintTest {

    @Test
    public void testParseFingerprintStructure() {
        // Create a mock fingerprint (62 chars)
        String fingerprint = "abc" + "def" + "ghi" + "jkl" + "mno" +
                "pqr" + "stu" + "vwx" + "yza" + "bcd" +
                "00112233445566778899aabbccddeeff";

        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);
        assertNotNull(components);

        assertEquals("abc", components.getProbeCode(1));
        assertEquals("def", components.getProbeCode(2));
        assertEquals("bcd", components.getProbeCode(10));
        assertEquals("00112233445566778899aabbccddeeff", components.getExtensionHash());
    }

    @Test
    public void testParseInvalidFingerprint() {
        assertNull(TlsServerFingerprint.parse(null));
        assertNull(TlsServerFingerprint.parse(""));
        assertNull(TlsServerFingerprint.parse("too_short"));
        assertNull(TlsServerFingerprint.parse("a".repeat(61))); // 61 chars
        assertNull(TlsServerFingerprint.parse("a".repeat(63))); // 63 chars
    }

    @Test
    public void testIsNoTlsSupport() {
        // All failed probes
        String noTls = "|||" + "|||" + "|||" + "|||" + "|||" +
                "|||" + "|||" + "|||" + "|||" + "|||" +
                "00000000000000000000000000000000";

        assertTrue(TlsServerFingerprint.isNoTlsSupport(noTls));

        // At least one successful probe
        String someTls = "a23" + "|||" + "|||" + "|||" + "|||" +
                "|||" + "|||" + "|||" + "|||" + "|||" +
                "00000000000000000000000000000000";

        assertFalse(TlsServerFingerprint.isNoTlsSupport(someTls));
    }

    @Test
    public void testSummarizeNoTls() {
        String noTls = "|||" + "|||" + "|||" + "|||" + "|||" +
                "|||" + "|||" + "|||" + "|||" + "|||" +
                "00000000000000000000000000000000";

        String summary = TlsServerFingerprint.summarize(noTls);
        assertTrue(summary.contains("No TLS"));
    }

    @Test
    public void testSummarizeWithTls() {
        // Mix of TLS 1.3 and TLS 1.2 responses
        String mixedTls = "a30" + "i20" + "|||" + "|||" + "|||" +
                "a30" + "|||" + "|||" + "|||" + "|||" +
                "00112233445566778899aabbccddeeff";

        String summary = TlsServerFingerprint.summarize(mixedTls);
        assertTrue(summary.contains("3/10")); // 3 successful probes
        assertTrue(summary.contains("TLS 1.3") || summary.contains("1.3"));
    }

    @Test
    public void testComponentsProbeSucceeded() {
        String fingerprint = "abc" + "|||" + "ghi" + "|||" + "mno" +
                "|||" + "|||" + "|||" + "|||" + "|||" +
                "00112233445566778899aabbccddeeff";

        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);

        assertTrue(components.probeSucceeded(1));
        assertFalse(components.probeSucceeded(2));
        assertTrue(components.probeSucceeded(3));
        assertFalse(components.probeSucceeded(4));
        assertTrue(components.probeSucceeded(5));
    }

    @Test
    public void testComponentsChars() {
        String fingerprint = "abc" + "def" + "ghi" + "jkl" + "mno" +
                "pqr" + "stu" + "vwx" + "yza" + "bcd" +
                "00112233445566778899aabbccddeeff";

        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);

        assertEquals("a", components.getCipherChar(1));
        assertEquals("b", components.getVersionChar(1));
        assertEquals("c", components.getExtensionChar(1));

        assertEquals("d", components.getCipherChar(2));
        assertEquals("e", components.getVersionChar(2));
        assertEquals("f", components.getExtensionChar(2));
    }

    @Test
    public void testComponentsInvalidProbeNumber() {
        String fingerprint = "abc" + "def" + "ghi" + "jkl" + "mno" +
                "pqr" + "stu" + "vwx" + "yza" + "bcd" +
                "00112233445566778899aabbccddeeff";

        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);

        assertThrows(IllegalArgumentException.class, () -> {
            components.getProbeCode(0);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            components.getProbeCode(11);
        });
    }

    @Test
    public void testComponentsToString() {
        String fingerprint = "a30" + "i20" + "|||" + "|||" + "|||" +
                "|||" + "|||" + "|||" + "|||" + "|||" +
                "00112233445566778899aabbccddeeff";

        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);
        String str = components.toString();

        assertTrue(str.contains("Probe 1"));
        assertTrue(str.contains("a30"));
        assertTrue(str.contains("Extension hash"));
        assertTrue(str.contains("00112233445566778899aabbccddeeff"));
    }

    @Test
    public void testSummarizeInvalid() {
        String summary = TlsServerFingerprint.summarize(null);
        assertTrue(summary.contains("Invalid"));

        summary = TlsServerFingerprint.summarize("short");
        assertTrue(summary.contains("Invalid"));
    }

    @Test
    public void testFingerprintLength() {
        // A valid TLS fingerprint is always exactly 62 characters:
        // 30 chars (10 probes x 3 chars) + 32 chars (SHA256 truncated to hex)
        int expectedLength = 62;

        String testFingerprint = "a".repeat(30) + "0".repeat(32);
        assertEquals(expectedLength, testFingerprint.length());

        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(testFingerprint);
        assertNotNull(components);
    }
}
