package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class TlsExtensionTest {

    @Test
    public void testExtensionCreation() {
        byte[] data = {0x01, 0x02, 0x03};
        TlsExtension ext = new TlsExtension(TlsExtension.SERVER_NAME, data);

        assertEquals(TlsExtension.SERVER_NAME, ext.getType());
        assertEquals(3, ext.getDataLength());
        assertArrayEquals(data, ext.getData());
    }

    @Test
    public void testExtensionTypeName() {
        TlsExtension ext = new TlsExtension(TlsExtension.SERVER_NAME, new byte[0]);
        assertEquals("server_name", ext.getTypeName());

        ext = new TlsExtension(TlsExtension.SUPPORTED_VERSIONS, new byte[0]);
        assertEquals("supported_versions", ext.getTypeName());

        ext = new TlsExtension(TlsExtension.KEY_SHARE, new byte[0]);
        assertEquals("key_share", ext.getTypeName());
    }

    @Test
    public void testGreaseDetection() {
        TlsExtension greaseExt = new TlsExtension(0x0a0a, new byte[0]);
        assertTrue(greaseExt.isGrease());
        assertEquals("GREASE", greaseExt.getTypeName());

        TlsExtension normalExt = new TlsExtension(TlsExtension.ALPN, new byte[0]);
        assertFalse(normalExt.isGrease());
    }

    @Test
    public void testIsGreaseValue() {
        assertTrue(TlsExtension.isGreaseValue(0x0a0a));
        assertTrue(TlsExtension.isGreaseValue(0x1a1a));
        assertTrue(TlsExtension.isGreaseValue(0xfafa));

        assertFalse(TlsExtension.isGreaseValue(0x0000));
        assertFalse(TlsExtension.isGreaseValue(0x002b));
    }

    @Test
    public void testDataCloning() {
        byte[] data = {0x01, 0x02, 0x03};
        TlsExtension ext = new TlsExtension(TlsExtension.SERVER_NAME, data);

        // Modify original data
        data[0] = (byte) 0x99;

        // Extension should still have original value
        byte[] extData = ext.getData();
        assertEquals(0x01, extData[0]);

        // Modify returned data
        extData[0] = (byte) 0x88;

        // Extension should still have original value
        assertEquals(0x01, ext.getData()[0]);
    }

    @Test
    public void testEquality() {
        byte[] data = {0x01, 0x02};
        TlsExtension ext1 = new TlsExtension(TlsExtension.ALPN, data);
        TlsExtension ext2 = new TlsExtension(TlsExtension.ALPN, data);
        TlsExtension ext3 = new TlsExtension(TlsExtension.SERVER_NAME, data);

        assertEquals(ext1, ext2);
        assertNotEquals(ext1, ext3);
        assertEquals(ext1.hashCode(), ext2.hashCode());
    }

    @Test
    public void testToString() {
        TlsExtension ext = new TlsExtension(TlsExtension.SUPPORTED_VERSIONS, new byte[2]);
        String str = ext.toString();

        assertTrue(str.contains("supported_versions"));
        assertTrue(str.contains("0x002b"));
        assertTrue(str.contains("2"));
    }

    @Test
    public void testUnknownExtension() {
        TlsExtension ext = new TlsExtension(0x9999, new byte[0]);
        assertTrue(ext.getTypeName().contains("unknown"));
        assertTrue(ext.getTypeName().contains("9999"));
    }

    @Test
    public void testAllExtensionConstants() {
        // Verify some key extension constants
        assertEquals(0x0000, TlsExtension.SERVER_NAME);
        assertEquals(0x0005, TlsExtension.STATUS_REQUEST);
        assertEquals(0x000a, TlsExtension.SUPPORTED_GROUPS);
        assertEquals(0x000d, TlsExtension.SIGNATURE_ALGORITHMS);
        assertEquals(0x0012, TlsExtension.SIGNED_CERT_TIMESTAMP);
        assertEquals(0x002b, TlsExtension.SUPPORTED_VERSIONS);
        assertEquals(0x0033, TlsExtension.KEY_SHARE);
    }
}
