package com.mps.deepviolet.api.tls;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class NamedGroupTest {

    @Test
    void testGetNameClassicalGroups() {
        assertEquals("X25519", NamedGroup.getName(NamedGroup.X25519));
        assertEquals("secp256r1", NamedGroup.getName(NamedGroup.SECP256R1));
        assertEquals("secp384r1", NamedGroup.getName(NamedGroup.SECP384R1));
        assertEquals("secp521r1", NamedGroup.getName(NamedGroup.SECP521R1));
        assertEquals("X448", NamedGroup.getName(NamedGroup.X448));
        assertEquals("ffdhe2048", NamedGroup.getName(NamedGroup.FFDHE2048));
        assertEquals("ffdhe3072", NamedGroup.getName(NamedGroup.FFDHE3072));
    }

    @Test
    void testGetNamePqGroups() {
        assertEquals("X25519MLKEM768", NamedGroup.getName(NamedGroup.X25519_MLKEM768));
        assertEquals("SecP256r1MLKEM768", NamedGroup.getName(NamedGroup.SECP256R1_MLKEM768));
        assertEquals("SecP384r1MLKEM1024", NamedGroup.getName(NamedGroup.SECP384R1_MLKEM1024));
        assertEquals("MLKEM768", NamedGroup.getName(NamedGroup.MLKEM768));
        assertEquals("MLKEM1024", NamedGroup.getName(NamedGroup.MLKEM1024));
    }

    @Test
    void testGetNameUnknownCode() {
        String name = NamedGroup.getName(0x9999);
        assertEquals("0x9999", name);
    }

    @Test
    void testIsPostQuantumTrue() {
        assertTrue(NamedGroup.isPostQuantum(NamedGroup.X25519_MLKEM768));
        assertTrue(NamedGroup.isPostQuantum(NamedGroup.SECP256R1_MLKEM768));
        assertTrue(NamedGroup.isPostQuantum(NamedGroup.SECP384R1_MLKEM1024));
        assertTrue(NamedGroup.isPostQuantum(NamedGroup.MLKEM768));
        assertTrue(NamedGroup.isPostQuantum(NamedGroup.MLKEM1024));
    }

    @Test
    void testIsPostQuantumFalse() {
        assertFalse(NamedGroup.isPostQuantum(NamedGroup.X25519));
        assertFalse(NamedGroup.isPostQuantum(NamedGroup.SECP256R1));
        assertFalse(NamedGroup.isPostQuantum(NamedGroup.SECP384R1));
        assertFalse(NamedGroup.isPostQuantum(NamedGroup.X448));
        assertFalse(NamedGroup.isPostQuantum(NamedGroup.FFDHE2048));
        assertFalse(NamedGroup.isPostQuantum(0x0000));
    }
}
