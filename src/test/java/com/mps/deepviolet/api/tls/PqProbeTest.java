package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for PQ probe configuration.
 * Network tests are marked {@code @Disabled}.
 */
public class PqProbeTest {

    @Test
    void testPqProbeConfigCiphers() {
        ClientHelloConfig config = ClientHelloConfig.pqProbe(NamedGroup.X25519_MLKEM768);
        // Should use TLS 1.3 ciphers only
        List<Integer> ciphers = config.getCipherSuites();
        assertFalse(ciphers.isEmpty());
        // All ciphers should be in the 0x13xx range (TLS 1.3)
        for (int cipher : ciphers) {
            assertTrue(cipher >= 0x1300 && cipher <= 0x13FF,
                    "Expected TLS 1.3 cipher, got: 0x" + Integer.toHexString(cipher));
        }
    }

    @Test
    void testPqProbeConfigGroupsSingleGroupOnly() {
        // Each probe should offer exactly the target PQ group — no classical fallback.
        // This eliminates server-preference ambiguity.
        for (int pqGroup : NamedGroup.PQ_GROUPS) {
            ClientHelloConfig config = ClientHelloConfig.pqProbe(pqGroup);
            List<Integer> groups = config.getSupportedGroups();
            assertEquals(1, groups.size(),
                    "Probe for " + NamedGroup.getName(pqGroup) + " should offer exactly 1 group");
            assertEquals(pqGroup, groups.get(0).intValue());
        }
    }

    @Test
    void testPqProbeConfigVersion() {
        ClientHelloConfig config = ClientHelloConfig.pqProbe(NamedGroup.X25519_MLKEM768);
        assertEquals(ClientHelloConfig.TLS_1_3, config.getTlsVersion());
        // Supported versions should be TLS 1.3 only
        List<Integer> versions = config.getSupportedVersions();
        assertEquals(1, versions.size());
        assertEquals(ClientHelloConfig.TLS_1_3, versions.get(0).intValue());
    }

    @Test
    void testPqProbeConfigIncludesEmptyKeyShare() {
        ClientHelloConfig config = ClientHelloConfig.pqProbe(NamedGroup.X25519_MLKEM768);
        assertTrue(config.isIncludeKeyShare());
        assertTrue(config.isEmptyKeyShare(), "PQ probe should use empty key_share to force HRR");
    }

    @Test
    void testAllPqGroupsHaveClassicalFallback() {
        for (int pqGroup : NamedGroup.PQ_GROUPS) {
            int fallback = NamedGroup.classicalFallback(pqGroup);
            assertFalse(NamedGroup.isPostQuantum(fallback),
                    "Fallback for " + NamedGroup.getName(pqGroup) + " should be classical");
        }
    }

    @Disabled("Requires live network connection")
    @Test
    void testPqProbeAgainstLiveServer() {
        List<Integer> result = TlsSocket.testPqSupport("www.google.com", 443);
        // Google supports PQ, so we expect a non-empty list
        assertNotNull(result, "PQ probe was inconclusive against google.com");
        assertFalse(result.isEmpty(), "Google should support at least one PQ group");
        assertTrue(result.contains(NamedGroup.X25519_MLKEM768),
                "Google should support X25519_MLKEM768");
    }
}
