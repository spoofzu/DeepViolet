package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class ClientHelloTest {

    @Test
    public void testBuild() {
        ClientHelloConfig config = ClientHelloConfig.defaultConfig();
        ClientHello clientHello = new ClientHello(config, "example.com");

        byte[] bytes = clientHello.build();

        assertNotNull(bytes);
        assertTrue(bytes.length > 50, "ClientHello should be at least 50 bytes");

        // First byte should be 0x01 (ClientHello type)
        assertEquals(0x01, bytes[0] & 0xFF);

        // Bytes 1-3 are length
        int length = ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
        assertEquals(bytes.length - 4, length, "Length field should match actual length");
    }

    @Test
    public void testClientRandom() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, "example.com");

        byte[] random = clientHello.getClientRandom();
        assertNotNull(random);
        assertEquals(32, random.length);

        // Verify it's cloned (not the internal array)
        random[0] = 0x00;
        assertNotEquals(0x00, clientHello.getClientRandom()[0]);
    }

    @Test
    public void testSetClientRandom() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, "example.com");

        byte[] custom = new byte[32];
        for (int i = 0; i < 32; i++) {
            custom[i] = (byte) i;
        }

        clientHello.setClientRandom(custom);
        assertArrayEquals(custom, clientHello.getClientRandom());
    }

    @Test
    public void testSetClientRandomInvalidLength() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, "example.com");

        assertThrows(IllegalArgumentException.class, () -> {
            clientHello.setClientRandom(new byte[16]);
        });
    }

    @Test
    public void testSessionId() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, "example.com");

        // Default session ID is empty
        assertEquals(0, clientHello.getSessionId().length);

        // Set custom session ID
        byte[] sessionId = {0x01, 0x02, 0x03, 0x04};
        clientHello.setSessionId(sessionId);
        assertArrayEquals(sessionId, clientHello.getSessionId());
    }

    @Test
    public void testRecordVersionTls12() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_2);
        ClientHello clientHello = new ClientHello(config, "example.com");

        assertEquals(0x0303, clientHello.getRecordVersion());
    }

    @Test
    public void testRecordVersionTls13() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_3);
        ClientHello clientHello = new ClientHello(config, "example.com");

        // TLS 1.3 uses 0x0303 (TLS 1.2) as record version for compatibility
        assertEquals(0x0303, clientHello.getRecordVersion());
    }

    @Test
    public void testRecordVersionTls10() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_0);
        ClientHello clientHello = new ClientHello(config, "example.com");

        assertEquals(0x0301, clientHello.getRecordVersion());
    }

    @Test
    public void testBuildContainsVersion() {
        ClientHelloConfig config = new ClientHelloConfig()
                .setTlsVersion(ClientHelloConfig.TLS_1_2);
        ClientHello clientHello = new ClientHello(config, "example.com");

        byte[] bytes = clientHello.build();

        // Version is at offset 4-5 (after header)
        int version = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
        assertEquals(0x0303, version);
    }

    @Test
    public void testBuildContainsRandom() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, "example.com");

        byte[] customRandom = new byte[32];
        for (int i = 0; i < 32; i++) {
            customRandom[i] = (byte) (0xAA ^ i);
        }
        clientHello.setClientRandom(customRandom);

        byte[] bytes = clientHello.build();

        // Random is at offset 6-37 (after header + version)
        for (int i = 0; i < 32; i++) {
            assertEquals(customRandom[i], bytes[6 + i],
                    "Random byte " + i + " mismatch");
        }
    }

    @Test
    public void testKeyShareKeyPair() {
        ClientHelloConfig config = ClientHelloConfig.defaultConfig()
                .setIncludeKeyShare(true);
        ClientHello clientHello = new ClientHello(config, "example.com");

        // Before build, key pair is null
        assertNull(clientHello.getKeyShareKeyPair());

        // After build, key pair should be generated
        clientHello.build();
        assertNotNull(clientHello.getKeyShareKeyPair());
        assertEquals("EC", clientHello.getKeyShareKeyPair().getPublic().getAlgorithm());
    }

    @Test
    public void testNullHostname() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, null);

        // Should not throw
        byte[] bytes = clientHello.build();
        assertNotNull(bytes);
    }

    @Test
    public void testEmptyHostname() {
        ClientHelloConfig config = new ClientHelloConfig();
        ClientHello clientHello = new ClientHello(config, "");

        // Should not throw
        byte[] bytes = clientHello.build();
        assertNotNull(bytes);
    }
}
