package com.mps.deepviolet.api.fingerprint;

import static org.junit.jupiter.api.Assertions.*;

import com.mps.deepviolet.api.tls.ClientHelloConfig;
import org.junit.jupiter.api.Test;

public class TlsBehaviorProbesTest {

    @Test
    public void testProbeCount() {
        assertEquals(10, TlsBehaviorProbes.PROBE_COUNT);
    }

    @Test
    public void testGetAllProbes() {
        for (int i = 1; i <= TlsBehaviorProbes.PROBE_COUNT; i++) {
            ClientHelloConfig config = TlsBehaviorProbes.getProbe(i);
            assertNotNull(config, "Probe " + i + " should not be null");
        }
    }

    @Test
    public void testGetProbeDescription() {
        for (int i = 1; i <= TlsBehaviorProbes.PROBE_COUNT; i++) {
            String desc = TlsBehaviorProbes.getProbeDescription(i);
            assertNotNull(desc, "Probe " + i + " description should not be null");
            assertFalse(desc.isEmpty(), "Probe " + i + " description should not be empty");
            assertFalse(desc.equals("Unknown probe"), "Probe " + i + " should have valid description");
        }
    }

    @Test
    public void testGetProbeDescriptionUnknown() {
        assertEquals("Unknown probe", TlsBehaviorProbes.getProbeDescription(0));
        assertEquals("Unknown probe", TlsBehaviorProbes.getProbeDescription(11));
        assertEquals("Unknown probe", TlsBehaviorProbes.getProbeDescription(-1));
    }

    @Test
    public void testIsValidProbeNumber() {
        assertFalse(TlsBehaviorProbes.isValidProbeNumber(0));
        assertTrue(TlsBehaviorProbes.isValidProbeNumber(1));
        assertTrue(TlsBehaviorProbes.isValidProbeNumber(5));
        assertTrue(TlsBehaviorProbes.isValidProbeNumber(10));
        assertFalse(TlsBehaviorProbes.isValidProbeNumber(11));
        assertFalse(TlsBehaviorProbes.isValidProbeNumber(-1));
    }

    @Test
    public void testProbeDescriptionsContent() {
        assertTrue(TlsBehaviorProbes.getProbeDescription(1).contains("TLS 1.2"));
        assertTrue(TlsBehaviorProbes.getProbeDescription(5).contains("TLS 1.1"));
        assertTrue(TlsBehaviorProbes.getProbeDescription(6).contains("TLS 1.3"));
    }
}
