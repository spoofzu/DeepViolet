package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Tests for ServerKeyExchange parsing.
 */
class ServerKeyExchangeTest {

    @Test
    void testParseDHE() {
        // Build a minimal DHE ServerKeyExchange:
        // dh_p: 2-byte length + prime bytes (256 bytes = 2048 bits)
        int pLen = 256;
        byte[] data = new byte[2 + pLen + 2 + 1 + 2 + 1]; // p + g + Ys (minimal)
        data[0] = (byte) ((pLen >> 8) & 0xFF);
        data[1] = (byte) (pLen & 0xFF);
        // First byte of prime is non-zero to ensure 2048 bits
        data[2] = (byte) 0x80;

        // DHE cipher suite: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E
        ServerKeyExchange ske = ServerKeyExchange.parse(data, 0x009E);
        assertEquals(ServerKeyExchange.KexType.DHE, ske.getKexType());
        assertEquals(2048, ske.getDhPrimeSizeBits());
    }

    @Test
    void testParseDHESmallPrime() {
        // 128 bytes = 1024 bits
        int pLen = 128;
        byte[] data = new byte[2 + pLen + 2 + 1 + 2 + 1];
        data[0] = (byte) ((pLen >> 8) & 0xFF);
        data[1] = (byte) (pLen & 0xFF);
        data[2] = (byte) 0xFF;

        ServerKeyExchange ske = ServerKeyExchange.parse(data, 0x009E);
        assertEquals(ServerKeyExchange.KexType.DHE, ske.getKexType());
        assertEquals(1024, ske.getDhPrimeSizeBits());
    }

    @Test
    void testParseECDHE() {
        // ECDHE ServerKeyExchange: curve_type=3, named_curve=0x0017 (secp256r1)
        byte[] data = new byte[] { 0x03, 0x00, 0x17, 0x41 };

        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
        ServerKeyExchange ske = ServerKeyExchange.parse(data, 0xC02F);
        assertEquals(ServerKeyExchange.KexType.ECDHE, ske.getKexType());
        assertEquals("secp256r1", ske.getEcCurveName());
        assertEquals(0x0017, ske.getEcCurveId());
    }

    @Test
    void testParseECDHEP384() {
        byte[] data = new byte[] { 0x03, 0x00, 0x18, 0x41 };
        ServerKeyExchange ske = ServerKeyExchange.parse(data, 0xC02F);
        assertEquals("secp384r1", ske.getEcCurveName());
    }

    @Test
    void testParseECDHEX25519() {
        byte[] data = new byte[] { 0x03, 0x00, 0x1D, 0x20 };
        ServerKeyExchange ske = ServerKeyExchange.parse(data, 0xC02F);
        assertEquals("x25519", ske.getEcCurveName());
    }

    @Test
    void testParseUnknownCipher() {
        byte[] data = new byte[] { 0x00, 0x01, 0x02 };
        // RSA cipher suite (no key exchange parsing)
        ServerKeyExchange ske = ServerKeyExchange.parse(data, 0x002F);
        assertEquals(ServerKeyExchange.KexType.UNKNOWN, ske.getKexType());
    }

    @Test
    void testParseNullData() {
        ServerKeyExchange ske = ServerKeyExchange.parse(null, 0x009E);
        assertEquals(ServerKeyExchange.KexType.UNKNOWN, ske.getKexType());
    }

    @Test
    void testParseTooShortData() {
        ServerKeyExchange ske = ServerKeyExchange.parse(new byte[1], 0x009E);
        assertEquals(ServerKeyExchange.KexType.UNKNOWN, ske.getKexType());
    }
}
