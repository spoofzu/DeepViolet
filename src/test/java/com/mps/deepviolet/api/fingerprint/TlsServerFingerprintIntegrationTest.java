package com.mps.deepviolet.api.fingerprint;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for TLS server fingerprinting.
 * These tests connect to real servers and require network access.
 */
@Disabled("Requires network access - run manually")
public class TlsServerFingerprintIntegrationTest {

    @Test
    public void testComputeTlsFingerprint() {
        String fingerprint = TlsServerFingerprint.compute("www.google.com", 443);

        assertNotNull(fingerprint);
        assertEquals(62, fingerprint.length(), "TLS fingerprint should be 62 characters");

        System.out.println("TLS fingerprint for www.google.com: " + fingerprint);

        // Parse and display components
        TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);
        assertNotNull(components);

        System.out.println("Probe codes:");
        for (int i = 1; i <= 10; i++) {
            String code = components.getProbeCode(i);
            boolean success = components.probeSucceeded(i);
            String desc = TlsBehaviorProbes.getProbeDescription(i);
            System.out.printf("  Probe %2d: %s (%s) - %s%n", i, code, success ? "OK" : "FAIL", desc);
        }
        System.out.println("Extension hash: " + components.getExtensionHash());
    }

    @Test
    public void testComputeTlsFingerprintDefaultPort() {
        String fingerprint = TlsServerFingerprint.compute("www.google.com");

        assertNotNull(fingerprint);
        assertEquals(62, fingerprint.length());

        // Should not be all failed
        assertFalse(TlsServerFingerprint.isNoTlsSupport(fingerprint),
                "Google should support TLS");
    }

    @Test
    public void testTlsFingerprintSummary() {
        String fingerprint = TlsServerFingerprint.compute("www.google.com", 443);

        String summary = TlsServerFingerprint.summarize(fingerprint);
        assertNotNull(summary);
        assertFalse(summary.contains("No TLS"), "Google should support TLS");

        System.out.println("Summary: " + summary);
    }

    @Test
    public void testTlsFingerprintForCloudflare() {
        String fingerprint = TlsServerFingerprint.compute("cloudflare.com", 443);

        assertNotNull(fingerprint);
        assertEquals(62, fingerprint.length());

        System.out.println("TLS fingerprint for cloudflare.com: " + fingerprint);
        System.out.println("Summary: " + TlsServerFingerprint.summarize(fingerprint));
    }

    @Test
    public void testTlsFingerprintForBadssl() {
        String fingerprint = TlsServerFingerprint.compute("www.badssl.com", 443);

        assertNotNull(fingerprint);
        assertEquals(62, fingerprint.length());

        System.out.println("TLS fingerprint for www.badssl.com: " + fingerprint);
        System.out.println("Summary: " + TlsServerFingerprint.summarize(fingerprint));
    }

    @Test
    public void testTlsFingerprintForNonExistentHost() {
        // This should return a fingerprint with all failed probes
        String fingerprint = TlsServerFingerprint.compute("nonexistent.invalid.test", 443);

        assertNotNull(fingerprint);
        assertEquals(62, fingerprint.length());

        // All probes should have failed
        assertTrue(TlsServerFingerprint.isNoTlsSupport(fingerprint),
                "Non-existent host should show no TLS support");

        System.out.println("TLS fingerprint for non-existent host: " + fingerprint);
    }

    @Test
    public void testTlsFingerprintConsistency() {
        // Run fingerprinting twice and compare - should be similar (server config may vary slightly)
        String fingerprint1 = TlsServerFingerprint.compute("www.google.com", 443);
        String fingerprint2 = TlsServerFingerprint.compute("www.google.com", 443);

        // Extension hash may vary due to timestamps, but probe codes should be similar
        TlsServerFingerprint.FingerprintComponents c1 = TlsServerFingerprint.parse(fingerprint1);
        TlsServerFingerprint.FingerprintComponents c2 = TlsServerFingerprint.parse(fingerprint2);

        int matchingProbes = 0;
        for (int i = 1; i <= 10; i++) {
            if (c1.getProbeCode(i).equals(c2.getProbeCode(i))) {
                matchingProbes++;
            }
        }

        // Most probes should match between runs
        assertTrue(matchingProbes >= 8,
                "At least 8 probe codes should match between runs, got " + matchingProbes);

        System.out.println("Fingerprint 1: " + fingerprint1);
        System.out.println("Fingerprint 2: " + fingerprint2);
        System.out.println("Matching probes: " + matchingProbes + "/10");
    }

    @Test
    public void testDifferentServicesHaveDifferentFingerprints() {
        String googleFingerprint = TlsServerFingerprint.compute("www.google.com", 443);
        String cloudflareFingerprint = TlsServerFingerprint.compute("cloudflare.com", 443);

        assertNotNull(googleFingerprint);
        assertNotNull(cloudflareFingerprint);

        // Different services should have different fingerprints
        // (though they might be similar if using same infrastructure)
        System.out.println("Google: " + googleFingerprint);
        System.out.println("Cloudflare: " + cloudflareFingerprint);

        if (!googleFingerprint.equals(cloudflareFingerprint)) {
            System.out.println("Fingerprints are different (expected)");
        } else {
            System.out.println("Fingerprints are same (possible if using similar TLS config)");
        }
    }
}
