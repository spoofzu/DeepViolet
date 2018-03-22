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
	public void testGetAlgorithm() {
		assertEquals("AES256GCM", cs.getAlgorithm());
	}

	@Test
	public void testGetIntegrity() {
		assertEquals("SHA384", cs.getIntegrity());
	}

}
