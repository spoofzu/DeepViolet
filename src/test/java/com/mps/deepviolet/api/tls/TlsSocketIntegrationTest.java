package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for TlsSocket.
 * These tests connect to real servers and require network access.
 */
@Disabled("Requires network access - run manually")
public class TlsSocketIntegrationTest {

    private static final String TEST_HOST = "www.google.com";
    private static final int TEST_PORT = 443;

    @Test
    public void testConnectAndHandshake() throws Exception {
        try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
            TlsMetadata metadata = socket.performHandshake();

            assertNotNull(metadata);
            assertTrue(metadata.isConnectionSucceeded(),
                    "Connection should succeed, failure: " + metadata.getFailureReason());
            assertTrue(metadata.getHandshakeTimeMs() > 0);
        }
    }

    @Test
    public void testServerHello() throws Exception {
        try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
            TlsMetadata metadata = socket.performHandshake();

            assertTrue(metadata.isConnectionSucceeded());

            ServerHello serverHello = metadata.getServerHello();
            assertNotNull(serverHello);
            assertTrue(serverHello.getCipherSuite() > 0);

            System.out.println("Version: " + serverHello.getVersionString());
            System.out.println("Cipher: " + serverHello.getCipherSuiteHex());
            System.out.println("Extensions: " + serverHello.getExtensions().size());
        }
    }

    @Test
    public void testTls13Support() throws Exception {
        ClientHelloConfig config = ClientHelloConfig.defaultConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_3)
                .setIncludeKeyShare(true);

        try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
            socket.setClientHelloConfig(config);
            TlsMetadata metadata = socket.performHandshake();

            assertTrue(metadata.isConnectionSucceeded());

            // Modern servers should support TLS 1.3
            if (metadata.isTLS13()) {
                System.out.println("TLS 1.3 negotiated successfully");
                assertEquals(0x0304, metadata.getNegotiatedVersion());
            } else {
                System.out.println("Server negotiated " + metadata.getVersionString() + " instead of TLS 1.3");
            }
        }
    }

    @Test
    public void testCertificateExtraction() throws Exception {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_2);

        try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
            socket.setClientHelloConfig(config);
            TlsMetadata metadata = socket.performHandshake();

            assertTrue(metadata.isConnectionSucceeded());

            // TLS 1.2 should give us certificates
            if (!metadata.isTLS13()) {
                List<X509Certificate> certs = metadata.getCertificateChain();
                assertNotNull(certs);
                assertFalse(certs.isEmpty(), "Should have at least one certificate");

                X509Certificate leafCert = certs.get(0);
                System.out.println("Subject: " + leafCert.getSubjectX500Principal());
                System.out.println("Issuer: " + leafCert.getIssuerX500Principal());
                System.out.println("Valid from: " + leafCert.getNotBefore());
                System.out.println("Valid until: " + leafCert.getNotAfter());
            }
        }
    }

    @Test
    public void testServerExtensions() throws Exception {
        try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
            TlsMetadata metadata = socket.performHandshake();

            assertTrue(metadata.isConnectionSucceeded());

            List<TlsExtension> extensions = metadata.getServerExtensions();
            assertNotNull(extensions);

            System.out.println("Server extensions (" + extensions.size() + "):");
            for (TlsExtension ext : extensions) {
                System.out.println("  - " + ext.getTypeName() + " (0x" +
                        Integer.toHexString(ext.getType()) + "), " + ext.getDataLength() + " bytes");
            }
        }
    }

    @Test
    public void testJarmCode() throws Exception {
        try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
            TlsMetadata metadata = socket.performHandshake();

            assertTrue(metadata.isConnectionSucceeded());

            String fingerprintCode = metadata.getFingerprintCode();
            assertNotNull(fingerprintCode);
            assertEquals(3, fingerprintCode.length());

            System.out.println("Fingerprint code: " + fingerprintCode);
            System.out.println("  Cipher: " + fingerprintCode.charAt(0));
            System.out.println("  Version: " + fingerprintCode.charAt(1));
            System.out.println("  Extension: " + fingerprintCode.charAt(2));
        }
    }

    @Test
    public void testStaticConnect() throws Exception {
        TlsMetadata metadata = TlsSocket.connect(TEST_HOST, TEST_PORT);

        assertNotNull(metadata);
        assertTrue(metadata.isConnectionSucceeded());
        assertEquals(TEST_HOST, metadata.getHost());
        assertEquals(TEST_PORT, metadata.getPort());
    }

    @Test
    public void testStaticGetCertificateChain() throws Exception {
        List<X509Certificate> certs = TlsSocket.getCertificateChain(TEST_HOST, TEST_PORT);

        // Note: This may be empty for TLS 1.3 since certs are encrypted
        assertNotNull(certs);
        System.out.println("Certificate chain size: " + certs.size());
    }

    @Test
    public void testDifferentTlsVersions() throws Exception {
        int[] versions = {
                ClientHelloConfig.TLS_1_0,
                ClientHelloConfig.TLS_1_1,
                ClientHelloConfig.TLS_1_2,
                ClientHelloConfig.TLS_1_3
        };

        for (int version : versions) {
            ClientHelloConfig config = new ClientHelloConfig()
                    .setTlsVersion(version);

            if (version >= ClientHelloConfig.TLS_1_3) {
                config.setIncludeKeyShare(true);
            }

            try (TlsSocket socket = new TlsSocket(TEST_HOST, TEST_PORT)) {
                socket.setClientHelloConfig(config);

                try {
                    TlsMetadata metadata = socket.performHandshake();

                    if (metadata.isConnectionSucceeded()) {
                        System.out.printf("Requested 0x%04x, got %s%n",
                                version, metadata.getVersionString());
                    } else {
                        System.out.printf("Requested 0x%04x, failed: %s%n",
                                version, metadata.getFailureReason());
                    }
                } catch (Exception e) {
                    System.out.printf("Requested 0x%04x, exception: %s%n",
                            version, e.getMessage());
                }
            }
        }
    }

    @Test
    public void testConnectionTimeout() throws Exception {
        try (TlsSocket socket = new TlsSocket("192.0.2.1", 443)) { // TEST-NET-1, should timeout
            socket.setConnectTimeoutMs(2000);

            TlsMetadata metadata = socket.performHandshake();

            assertFalse(metadata.isConnectionSucceeded());
            assertNotNull(metadata.getFailureReason());
            System.out.println("Timeout failure: " + metadata.getFailureReason());
        }
    }

    @Test
    public void testNonTlsServer() throws Exception {
        try (TlsSocket socket = new TlsSocket("www.google.com", 80)) { // HTTP, not HTTPS
            socket.setReadTimeoutMs(3000);

            try {
                TlsMetadata metadata = socket.performHandshake();
                // Either should fail or not succeed
                assertFalse(metadata.isConnectionSucceeded() &&
                        metadata.getServerHello() != null);
            } catch (TlsException e) {
                // Expected - not a TLS server
                System.out.println("Expected failure on non-TLS port: " + e.getMessage());
            }
        }
    }
}
