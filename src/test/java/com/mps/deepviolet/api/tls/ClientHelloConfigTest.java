package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

public class ClientHelloConfigTest {

    @Test
    public void testDefaultConfig() {
        ClientHelloConfig config = ClientHelloConfig.defaultConfig();

        assertEquals(ClientHelloConfig.TLS_1_3, config.getTlsVersion());
        assertTrue(config.isIncludeKeyShare());
        assertTrue(config.isIncludeStatusRequest());
        assertFalse(config.getCipherSuites().isEmpty());
    }

    @Test
    public void testBuilderPattern() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_2)
                .setAlpnProtocol("h2")
                .setIncludeGrease(true)
                .setIncludeKeyShare(false);

        assertEquals(ClientHelloConfig.TLS_1_2, config.getTlsVersion());
        assertEquals("h2", config.getAlpnProtocol());
        assertTrue(config.isIncludeGrease());
        assertFalse(config.isIncludeKeyShare());
    }

    @Test
    public void testVersionConstants() {
        assertEquals(0x0300, ClientHelloConfig.SSL_3_0);
        assertEquals(0x0301, ClientHelloConfig.TLS_1_0);
        assertEquals(0x0302, ClientHelloConfig.TLS_1_1);
        assertEquals(0x0303, ClientHelloConfig.TLS_1_2);
        assertEquals(0x0304, ClientHelloConfig.TLS_1_3);
    }

    @Test
    public void testSetCipherSuites() {
        List<Integer> ciphers = Arrays.asList(0x1301, 0x1302, 0x1303);
        ClientHelloConfig config = new ClientHelloConfig()
                .setCipherSuites(ciphers);

        assertEquals(3, config.getCipherSuites().size());
        assertTrue(config.getCipherSuites().contains(0x1301));
    }

    @Test
    public void testCipherSuitesImmutable() {
        List<Integer> ciphers = Arrays.asList(0x1301, 0x1302);
        ClientHelloConfig config = new ClientHelloConfig()
                .setCipherSuites(ciphers);

        // Returned list should be unmodifiable
        assertThrows(UnsupportedOperationException.class, () -> {
            config.getCipherSuites().add(0x1303);
        });
    }

    @Test
    public void testSupportedVersions() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_3)
                .setSupportedVersions(Arrays.asList(
                        ClientHelloConfig.TLS_1_3,
                        ClientHelloConfig.TLS_1_2));

        List<Integer> versions = config.getSupportedVersions();
        assertEquals(2, versions.size());
        assertTrue(versions.contains(ClientHelloConfig.TLS_1_3));
        assertTrue(versions.contains(ClientHelloConfig.TLS_1_2));
    }

    @Test
    public void testDefaultSupportedVersions() {
        ClientHelloConfig configTls13 = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_3);
        // TLS 1.3 should default to listing multiple versions
        assertTrue(configTls13.getSupportedVersions().size() > 1);

        ClientHelloConfig configTls12 = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_2);
        // TLS 1.2 should default to just that version
        assertEquals(1, configTls12.getSupportedVersions().size());
    }

    @Test
    public void testBehaviorProbe1() {
        ClientHelloConfig config = ClientHelloConfig.behaviorProbe1();
        assertEquals(ClientHelloConfig.TLS_1_2, config.getTlsVersion());
        assertFalse(config.getCipherSuites().isEmpty());
    }

    @Test
    public void testBehaviorProbe6() {
        ClientHelloConfig config = ClientHelloConfig.behaviorProbe6();
        assertEquals(ClientHelloConfig.TLS_1_3, config.getTlsVersion());
        assertTrue(config.isIncludeKeyShare());
        // Should only have TLS 1.3 ciphers
        for (int cipher : config.getCipherSuites()) {
            assertTrue(cipher >= 0x1301 && cipher <= 0x1305,
                    "Expected TLS 1.3 cipher, got: 0x" + Integer.toHexString(cipher));
        }
    }

    @Test
    public void testBehaviorProbeMethod() {
        // Test all 10 probes
        for (int i = 1; i <= 10; i++) {
            ClientHelloConfig config = ClientHelloConfig.behaviorProbe(i);
            assertNotNull(config, "Probe " + i + " should not be null");
            assertFalse(config.getCipherSuites().isEmpty(),
                    "Probe " + i + " should have cipher suites");
        }
    }

    @Test
    public void testBehaviorProbeInvalidNumber() {
        assertThrows(IllegalArgumentException.class, () -> {
            ClientHelloConfig.behaviorProbe(0);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            ClientHelloConfig.behaviorProbe(11);
        });
    }

    @Test
    public void testBehaviorProbe2ReverseOrder() {
        ClientHelloConfig probe1 = ClientHelloConfig.behaviorProbe1();
        ClientHelloConfig probe2 = ClientHelloConfig.behaviorProbe2();

        List<Integer> ciphers1 = probe1.getCipherSuites();
        List<Integer> ciphers2 = probe2.getCipherSuites();

        assertEquals(ciphers1.size(), ciphers2.size());

        // First cipher of probe1 should be last cipher of probe2
        assertEquals(ciphers1.get(0), ciphers2.get(ciphers2.size() - 1));
    }

    @Test
    public void testBehaviorProbe3HasAlpn() {
        ClientHelloConfig config = ClientHelloConfig.behaviorProbe3();
        assertEquals("h2", config.getAlpnProtocol());
    }

    @Test
    public void testBehaviorProbe4NoEcc() {
        ClientHelloConfig config = ClientHelloConfig.behaviorProbe4();
        assertFalse(config.isIncludeSupportedGroups());
        assertFalse(config.isIncludeEcPointFormats());
    }

    @Test
    public void testBehaviorProbe5Tls11() {
        ClientHelloConfig config = ClientHelloConfig.behaviorProbe5();
        assertEquals(ClientHelloConfig.TLS_1_1, config.getTlsVersion());
    }

    @Test
    public void testSupportedGroups() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setSupportedGroups(Arrays.asList(0x0017, 0x0018));

        List<Integer> groups = config.getSupportedGroups();
        assertEquals(2, groups.size());
        assertTrue(groups.contains(0x0017)); // secp256r1
        assertTrue(groups.contains(0x0018)); // secp384r1
    }
}
