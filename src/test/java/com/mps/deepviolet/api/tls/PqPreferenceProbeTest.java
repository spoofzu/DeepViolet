package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the PQ preference probe configuration.
 * Network tests are marked {@code @Disabled}.
 */
public class PqPreferenceProbeTest {

    @Test
    void testPqPreferenceProbeOffersExactlyFourGroups() {
        ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();
        List<Integer> groups = config.getSupportedGroups();
        assertEquals(4, groups.size(), "Preference probe should offer exactly 4 groups");
    }

    @Test
    void testPqPreferenceProbePqGroupsListedFirst() {
        ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();
        List<Integer> groups = config.getSupportedGroups();

        // First two should be PQ hybrid
        assertTrue(NamedGroup.isPostQuantum(groups.get(0)),
                "First group should be PQ: " + NamedGroup.getName(groups.get(0)));
        assertTrue(NamedGroup.isPostQuantum(groups.get(1)),
                "Second group should be PQ: " + NamedGroup.getName(groups.get(1)));

        // Last two should be classical
        assertFalse(NamedGroup.isPostQuantum(groups.get(2)),
                "Third group should be classical: " + NamedGroup.getName(groups.get(2)));
        assertFalse(NamedGroup.isPostQuantum(groups.get(3)),
                "Fourth group should be classical: " + NamedGroup.getName(groups.get(3)));
    }

    @Test
    void testPqPreferenceProbeSpecificGroups() {
        ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();
        List<Integer> groups = config.getSupportedGroups();

        assertEquals(NamedGroup.X25519_MLKEM768, groups.get(0).intValue());
        assertEquals(NamedGroup.SECP256R1_MLKEM768, groups.get(1).intValue());
        assertEquals(NamedGroup.X25519, groups.get(2).intValue());
        assertEquals(NamedGroup.SECP256R1, groups.get(3).intValue());
    }

    @Test
    void testPqPreferenceProbeTls13Only() {
        ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();
        assertEquals(ClientHelloConfig.TLS_1_3, config.getTlsVersion());

        List<Integer> versions = config.getSupportedVersions();
        assertEquals(1, versions.size());
        assertEquals(ClientHelloConfig.TLS_1_3, versions.get(0).intValue());
    }

    @Test
    void testPqPreferenceProbeEmptyKeyShare() {
        ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();
        assertTrue(config.isIncludeKeyShare());
        assertTrue(config.isEmptyKeyShare(), "Preference probe should use empty key_share to force HRR");
    }

    @Test
    void testPqPreferenceProbeCiphers() {
        ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();
        List<Integer> ciphers = config.getCipherSuites();
        assertFalse(ciphers.isEmpty());
        for (int cipher : ciphers) {
            assertTrue(cipher >= 0x1300 && cipher <= 0x13FF,
                    "Expected TLS 1.3 cipher, got: 0x" + Integer.toHexString(cipher));
        }
    }

    @Disabled("Requires live network connection")
    @Test
    void testPqPreferenceProbeAgainstLiveServer() {
        Integer result = TlsSocket.testPqPreference("www.google.com", 443);
        // Google is known to prefer PQ groups
        assertNotNull(result, "PQ preference probe was inconclusive against google.com");
        assertTrue(NamedGroup.isPostQuantum(result),
                "Google should prefer a PQ group, got: " + NamedGroup.getName(result));
    }
}
