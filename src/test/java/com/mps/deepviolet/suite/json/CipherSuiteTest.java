package com.mps.deepviolet.suite.json;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CipherSuiteTest {

	private final CipherSuite cs = new com.mps.deepviolet.suite.json.CipherSuite("ECDHE-ECDSA-AES256-GCM-SHA384");

	@Test
	public void testGetKeyExchange() {
		assertEquals("ECDHE", cs.getKeyExchange());
	}

	@Test
	public void testGetAuthentication() {
		assertEquals("ECDSA", cs.getAuthentication());
	}

	@Test
	public void testGetAlgorythm() {
		assertEquals("AES256GCM", cs.getAlgorythm());
	}

	@Test
	public void testGetIntegrity() {
		assertEquals("SHA384", cs.getIntegrity());
	}

}
