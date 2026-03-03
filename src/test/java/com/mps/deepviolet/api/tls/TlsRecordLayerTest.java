package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

public class TlsRecordLayerTest {

    @Test
    public void testEnc16be() {
        byte[] buf = new byte[2];
        TlsRecordLayer.enc16be(0x0303, buf, 0);
        assertEquals(0x03, buf[0] & 0xFF);
        assertEquals(0x03, buf[1] & 0xFF);

        TlsRecordLayer.enc16be(0xFFFF, buf, 0);
        assertEquals(0xFF, buf[0] & 0xFF);
        assertEquals(0xFF, buf[1] & 0xFF);
    }

    @Test
    public void testDec16be() {
        byte[] buf = {0x03, 0x03};
        assertEquals(0x0303, TlsRecordLayer.dec16be(buf, 0));

        buf = new byte[]{(byte)0xFF, (byte)0xFF};
        assertEquals(0xFFFF, TlsRecordLayer.dec16be(buf, 0));
    }

    @Test
    public void testEnc24be() {
        byte[] buf = new byte[3];
        TlsRecordLayer.enc24be(0x010203, buf, 0);
        assertEquals(0x01, buf[0] & 0xFF);
        assertEquals(0x02, buf[1] & 0xFF);
        assertEquals(0x03, buf[2] & 0xFF);
    }

    @Test
    public void testDec24be() {
        byte[] buf = {0x01, 0x02, 0x03};
        assertEquals(0x010203, TlsRecordLayer.dec24be(buf, 0));
    }

    @Test
    public void testEnc32be() {
        byte[] buf = new byte[4];
        TlsRecordLayer.enc32be(0x01020304, buf, 0);
        assertEquals(0x01, buf[0] & 0xFF);
        assertEquals(0x02, buf[1] & 0xFF);
        assertEquals(0x03, buf[2] & 0xFF);
        assertEquals(0x04, buf[3] & 0xFF);
    }

    @Test
    public void testDec32be() {
        byte[] buf = {0x01, 0x02, 0x03, 0x04};
        assertEquals(0x01020304, TlsRecordLayer.dec32be(buf, 0));
    }

    @Test
    public void testEnc16beStream() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsRecordLayer.enc16be(0x0303, out);
        byte[] result = out.toByteArray();
        assertEquals(2, result.length);
        assertEquals(0x03, result[0] & 0xFF);
        assertEquals(0x03, result[1] & 0xFF);
    }

    @Test
    public void testRecordTypeConstants() {
        assertEquals(20, TlsRecordLayer.CHANGE_CIPHER_SPEC);
        assertEquals(21, TlsRecordLayer.ALERT);
        assertEquals(22, TlsRecordLayer.HANDSHAKE);
        assertEquals(23, TlsRecordLayer.APPLICATION_DATA);
    }

    @Test
    public void testHandshakeTypeConstants() {
        assertEquals(1, TlsRecordLayer.HANDSHAKE_CLIENT_HELLO);
        assertEquals(2, TlsRecordLayer.HANDSHAKE_SERVER_HELLO);
        assertEquals(11, TlsRecordLayer.HANDSHAKE_CERTIFICATE);
        assertEquals(14, TlsRecordLayer.HANDSHAKE_SERVER_HELLO_DONE);
        assertEquals(22, TlsRecordLayer.HANDSHAKE_CERTIFICATE_STATUS);
    }

    @Test
    public void testGetHandshakeTypeName() {
        assertEquals("ClientHello", TlsRecordLayer.getHandshakeTypeName(1));
        assertEquals("ServerHello", TlsRecordLayer.getHandshakeTypeName(2));
        assertEquals("Certificate", TlsRecordLayer.getHandshakeTypeName(11));
        assertEquals("ServerHelloDone", TlsRecordLayer.getHandshakeTypeName(14));
        assertTrue(TlsRecordLayer.getHandshakeTypeName(99).contains("Unknown"));
    }

    @Test
    public void testGetRecordTypeName() {
        assertEquals("ChangeCipherSpec", TlsRecordLayer.getRecordTypeName(20));
        assertEquals("Alert", TlsRecordLayer.getRecordTypeName(21));
        assertEquals("Handshake", TlsRecordLayer.getRecordTypeName(22));
        assertEquals("ApplicationData", TlsRecordLayer.getRecordTypeName(23));
        assertTrue(TlsRecordLayer.getRecordTypeName(99).contains("Unknown"));
    }

    @Test
    public void testMaxRecordLen() {
        assertEquals(16384, TlsRecordLayer.MAX_RECORD_LEN);
    }

    @Test
    public void testHandshakeMessage() {
        byte[] data = {0x01, 0x02, 0x03};
        TlsRecordLayer.HandshakeMessage msg =
                new TlsRecordLayer.HandshakeMessage(2, data, 0x0303);

        assertEquals(2, msg.getType());
        assertEquals("ServerHello", msg.getTypeName());
        assertEquals(0x0303, msg.getRecordVersion());
        assertArrayEquals(data, msg.getData());
    }
}
