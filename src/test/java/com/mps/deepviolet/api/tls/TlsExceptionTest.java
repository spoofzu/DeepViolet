package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class TlsExceptionTest {

    @Test
    public void testSimpleMessage() {
        TlsException ex = new TlsException("Test error");
        assertEquals("Test error", ex.getMessage());
        assertFalse(ex.isAlertException());
    }

    @Test
    public void testMessageWithCause() {
        Exception cause = new RuntimeException("root cause");
        TlsException ex = new TlsException("Test error", cause);
        assertEquals("Test error", ex.getMessage());
        assertEquals(cause, ex.getCause());
    }

    @Test
    public void testAlertException() {
        TlsException ex = new TlsException(2, 40); // fatal, handshake_failure
        assertTrue(ex.isAlertException());
        assertEquals(2, ex.getAlertLevel());
        assertEquals(40, ex.getAlertDescription());
        assertTrue(ex.isFatalAlert());
    }

    @Test
    public void testWarningAlert() {
        TlsException ex = new TlsException(1, 0); // warning, close_notify
        assertTrue(ex.isAlertException());
        assertEquals(1, ex.getAlertLevel());
        assertFalse(ex.isFatalAlert());
    }

    @Test
    public void testAlertExceptionMessage() {
        TlsException ex = new TlsException(2, 40);
        String msg = ex.getMessage();
        assertTrue(msg.contains("fatal"));
        assertTrue(msg.contains("handshake_failure"));
        assertTrue(msg.contains("40"));
    }

    @Test
    public void testAlertExceptionWithContext() {
        TlsException ex = new TlsException("Connection failed", 2, 70);
        String msg = ex.getMessage();
        assertTrue(msg.contains("Connection failed"));
        assertTrue(msg.contains("protocol_version"));
    }

    @Test
    public void testGetAlertDescriptionName() {
        assertEquals("close_notify", TlsException.getAlertDescriptionName(0));
        assertEquals("handshake_failure", TlsException.getAlertDescriptionName(40));
        assertEquals("bad_certificate", TlsException.getAlertDescriptionName(42));
        assertEquals("certificate_expired", TlsException.getAlertDescriptionName(45));
        assertEquals("protocol_version", TlsException.getAlertDescriptionName(70));
        assertEquals("internal_error", TlsException.getAlertDescriptionName(80));
        assertEquals("unknown", TlsException.getAlertDescriptionName(999));
    }

    @Test
    public void testNonAlertExceptionDefaults() {
        TlsException ex = new TlsException("Test");
        assertEquals(-1, ex.getAlertLevel());
        assertEquals(-1, ex.getAlertDescription());
    }

    @Test
    public void testCommonAlerts() {
        // Test some commonly seen alerts
        assertEquals("unexpected_message",
                TlsException.getAlertDescriptionName(10));
        assertEquals("bad_record_mac",
                TlsException.getAlertDescriptionName(20));
        assertEquals("decode_error",
                TlsException.getAlertDescriptionName(50));
        assertEquals("illegal_parameter",
                TlsException.getAlertDescriptionName(47));
        assertEquals("insufficient_security",
                TlsException.getAlertDescriptionName(71));
    }
}
