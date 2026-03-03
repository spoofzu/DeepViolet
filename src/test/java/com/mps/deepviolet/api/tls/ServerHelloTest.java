package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

public class ServerHelloTest {

    // Minimal valid ServerHello bytes (TLS 1.2)
    // Version: 0x0303
    // Random: 32 bytes of 0x00
    // Session ID: length 0
    // Cipher: 0xc02f (ECDHE-RSA-AES128-GCM-SHA256)
    // Compression: 0x00
    // Extensions: none
    private static final byte[] MINIMAL_SERVER_HELLO = {
            0x03, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // session ID length
            (byte)0xc0, 0x2f, // cipher suite
            0x00 // compression
    };

    // ServerHello with extensions
    private static final byte[] SERVER_HELLO_WITH_EXT = {
            0x03, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // session ID length
            (byte)0xc0, 0x2f, // cipher suite
            0x00, // compression
            0x00, 0x09, // extensions length
            // Extension: renegotiation_info
            (byte)0xff, 0x01, // type
            0x00, 0x01, // length
            0x00, // data
            // Extension: extended_master_secret
            0x00, 0x17, // type
            0x00, 0x00  // length (empty)
    };

    // TLS 1.3 ServerHello with supported_versions extension
    private static final byte[] TLS13_SERVER_HELLO = {
            0x03, 0x03, // legacy version (TLS 1.2)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // session ID length
            0x13, 0x01, // cipher suite (TLS_AES_128_GCM_SHA256)
            0x00, // compression
            0x00, 0x06, // extensions length
            // Extension: supported_versions
            0x00, 0x2b, // type
            0x00, 0x02, // length
            0x03, 0x04  // TLS 1.3
    };

    @Test
    public void testMinimalServerHello() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);

        assertEquals(0x0303, sh.getProtocolVersion());
        assertEquals(0x0303, sh.getNegotiatedVersion());
        assertEquals(0xc02f, sh.getCipherSuite());
        assertEquals(0, sh.getCompression());
        assertFalse(sh.isTLS13());
        assertTrue(sh.getExtensions().isEmpty());
    }

    @Test
    public void testServerRandom() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);

        byte[] random = sh.getServerRandom();
        assertNotNull(random);
        assertEquals(32, random.length);
    }

    @Test
    public void testSessionId() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);

        byte[] sessionId = sh.getSessionId();
        assertNotNull(sessionId);
        assertEquals(0, sessionId.length);
    }

    @Test
    public void testServerHelloWithExtensions() throws TlsException {
        ServerHello sh = new ServerHello(SERVER_HELLO_WITH_EXT, 0x0303);

        assertEquals(2, sh.getExtensions().size());

        // Check renegotiation_info extension
        assertTrue(sh.hasExtension(TlsExtension.RENEGOTIATION_INFO));
        byte[] renego = sh.getExtensionData(TlsExtension.RENEGOTIATION_INFO);
        assertNotNull(renego);
        assertEquals(1, renego.length);

        // Check extended_master_secret extension
        assertTrue(sh.hasExtension(TlsExtension.EXTENDED_MASTER_SECRET));
        byte[] ems = sh.getExtensionData(TlsExtension.EXTENDED_MASTER_SECRET);
        assertNotNull(ems);
        assertEquals(0, ems.length);
    }

    @Test
    public void testTls13ServerHello() throws TlsException {
        ServerHello sh = new ServerHello(TLS13_SERVER_HELLO, 0x0303);

        assertEquals(0x0303, sh.getProtocolVersion()); // Legacy version
        assertEquals(0x0304, sh.getNegotiatedVersion()); // Real version from extension
        assertEquals(0x1301, sh.getCipherSuite());
        assertTrue(sh.isTLS13());
        assertTrue(sh.hasExtension(TlsExtension.SUPPORTED_VERSIONS));
    }

    @Test
    public void testVersionString() throws TlsException {
        ServerHello sh12 = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);
        assertEquals("TLSv1.2", sh12.getVersionString());

        ServerHello sh13 = new ServerHello(TLS13_SERVER_HELLO, 0x0303);
        assertEquals("TLSv1.3", sh13.getVersionString());
    }

    @Test
    public void testCipherSuiteHex() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);
        assertEquals("0xc02f", sh.getCipherSuiteHex());
    }

    @Test
    public void testFingerprintCode() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);

        String code = sh.getFingerprintCode();
        assertNotNull(code);
        assertEquals(3, code.length());

        // Second character should be version: '2' for TLS 1.2
        assertEquals('2', code.charAt(1));
    }

    @Test
    public void testFingerprintCodeTls13() throws TlsException {
        ServerHello sh = new ServerHello(TLS13_SERVER_HELLO, 0x0303);

        String code = sh.getFingerprintCode();
        assertNotNull(code);
        assertEquals(3, code.length());

        // First character should be 'a' for TLS_AES_128_GCM_SHA256 (0x1301)
        assertEquals('a', code.charAt(0));
        // Second character should be version: '3' for TLS 1.3
        assertEquals('3', code.charAt(1));
    }

    @Test
    public void testExtensionTypes() throws TlsException {
        ServerHello sh = new ServerHello(SERVER_HELLO_WITH_EXT, 0x0303);

        List<Integer> types = sh.getExtensionTypes();
        assertEquals(2, types.size());
        assertTrue(types.contains(TlsExtension.RENEGOTIATION_INFO));
        assertTrue(types.contains(TlsExtension.EXTENDED_MASTER_SECRET));
    }

    @Test
    public void testRawExtensions() throws TlsException {
        ServerHello sh = new ServerHello(SERVER_HELLO_WITH_EXT, 0x0303);

        byte[] raw = sh.getRawExtensions();
        assertNotNull(raw);
        assertEquals(9, raw.length); // Same as extensions length in the message
    }

    @Test
    public void testExtensionsHash() throws TlsException {
        ServerHello sh = new ServerHello(SERVER_HELLO_WITH_EXT, 0x0303);

        byte[] hash = sh.getExtensionsHash();
        assertNotNull(hash);
        assertEquals(16, hash.length); // Truncated to 16 bytes
    }

    @Test
    public void testNoExtensionData() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);

        assertFalse(sh.hasExtension(TlsExtension.ALPN));
        assertNull(sh.getExtensionData(TlsExtension.ALPN));
    }

    @Test
    public void testToString() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0303);

        String str = sh.toString();
        assertTrue(str.contains("TLSv1.2"));
        assertTrue(str.contains("0xc02f"));
    }

    @Test
    public void testInvalidServerHelloTooShort() {
        byte[] tooShort = {0x03, 0x03}; // Only version, missing random

        assertThrows(TlsException.class, () -> {
            new ServerHello(tooShort, 0x0303);
        });
    }

    @Test
    public void testRecordVersion() throws TlsException {
        ServerHello sh = new ServerHello(MINIMAL_SERVER_HELLO, 0x0302);
        assertEquals(0x0302, sh.getRecordVersion());
    }
}
