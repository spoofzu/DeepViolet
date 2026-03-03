package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

public class CipherMapTest {

	@Test
	public void testCiphermapYamlLoads() {
		Map<String, Object> root = loadCiphermap();
		assertNotNull(root);
		assertTrue(root.containsKey("metadata"));
		assertTrue(root.containsKey("cipher_suites"));

		@SuppressWarnings("unchecked")
		List<Map<String, Object>> suites = (List<Map<String, Object>>) root.get("cipher_suites");
		assertTrue(suites.size() > 300, "Expected at least 300 cipher suites");
	}

	@Test
	public void testParseHexIdTwoBytes() {
		assertEquals(0x0000, CipherSuiteUtil.parseHexId("0x00,0x00"));
		assertEquals(0x002F, CipherSuiteUtil.parseHexId("0x00,0x2F"));
		assertEquals(0x0035, CipherSuiteUtil.parseHexId("0x00,0x35"));
		assertEquals(0x000A, CipherSuiteUtil.parseHexId("0x00,0x0A"));
	}

	@Test
	public void testParseHexIdHighByteCiphers() {
		assertEquals(0xC009, CipherSuiteUtil.parseHexId("0xC0,0x09"));
		assertEquals(0xC02B, CipherSuiteUtil.parseHexId("0xC0,0x2B"));
		assertEquals(0xC02F, CipherSuiteUtil.parseHexId("0xC0,0x2F"));
		assertEquals(0xCC13, CipherSuiteUtil.parseHexId("0xCC,0x13"));
	}

	@Test
	public void testParseHexIdTls13() {
		assertEquals(0x1301, CipherSuiteUtil.parseHexId("0x13,0x01"));
		assertEquals(0x1302, CipherSuiteUtil.parseHexId("0x13,0x02"));
		assertEquals(0x1303, CipherSuiteUtil.parseHexId("0x13,0x03"));
		assertEquals(0x1304, CipherSuiteUtil.parseHexId("0x13,0x04"));
		assertEquals(0x1305, CipherSuiteUtil.parseHexId("0x13,0x05"));
	}

	@Test
	public void testParseHexIdSslv2ThreeBytes() {
		assertEquals(0x010080, CipherSuiteUtil.parseHexId("0x01,0x00,0x80"));
		assertEquals(0x0700C0, CipherSuiteUtil.parseHexId("0x07,0x00,0xC0"));
	}

	@Test
	public void testParseHexIdInvalid() {
		assertThrows(IllegalArgumentException.class, () ->
			CipherSuiteUtil.parseHexId("0x01"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testKnownCipherStrengths() {
		Map<String, Object> root = loadCiphermap();
		List<Map<String, Object>> suites = (List<Map<String, Object>>) root.get("cipher_suites");

		boolean foundTls13 = false;
		boolean foundEcdheGcm = false;
		boolean foundNull = false;

		for (Map<String, Object> suite : suites) {
			String id = (String) suite.get("id");
			String strength = (String) suite.get("strength");
			Map<String, String> names = (Map<String, String>) suite.get("names");
			String iana = names.get("IANA");

			if (id.equals("0x13,0x01")) {
				assertEquals("STRONG", strength, "TLS 1.3 AES-128-GCM should be STRONG");
				assertEquals("TLS_AES_128_GCM_SHA256", iana);
				foundTls13 = true;
			}
			if (id.equals("0xC0,0x2B")) {
				assertEquals("MEDIUM", strength, "ECDHE-ECDSA-AES128-GCM should be MEDIUM");
				foundEcdheGcm = true;
			}
			if (id.equals("0x00,0x00")) {
				assertEquals("CLEAR", strength, "NULL cipher should be CLEAR");
				foundNull = true;
			}
		}

		assertTrue(foundTls13, "TLS 1.3 cipher 0x13,0x01 should be present");
		assertTrue(foundEcdheGcm, "ECDHE-GCM cipher 0xC0,0x2B should be present");
		assertTrue(foundNull, "NULL cipher 0x00,0x00 should be present");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testTls13CiphersAtCorrectIds() {
		Map<String, Object> root = loadCiphermap();
		List<Map<String, Object>> suites = (List<Map<String, Object>>) root.get("cipher_suites");

		for (Map<String, Object> suite : suites) {
			int suiteId = CipherSuiteUtil.parseHexId((String) suite.get("id"));
			if (suiteId == 0x1301) {
				Map<String, String> names = (Map<String, String>) suite.get("names");
				assertEquals("TLS_AES_128_GCM_SHA256", names.get("IANA"));
				return;
			}
		}
		fail("TLS 1.3 cipher 0x1301 not found in ciphermap.yaml");
	}

	@AfterEach
	public void tearDown() throws Exception {
		DeepVioletFactory.resetCipherMap();
	}

	@Test
	public void testLoadCipherMapFromStream() throws Exception {
		String yaml = """
				metadata:
				  version: "1.0"
				cipher_suites:
				  - id: "0x00,0x2F"
				    strength: STRONG
				    names:
				      IANA: TLS_RSA_WITH_AES_128_CBC_SHA
				      OpenSSL: AES128-SHA
				  - id: "0x00,0x35"
				    strength: STRONG
				    names:
				      IANA: TLS_RSA_WITH_AES_256_CBC_SHA
				      OpenSSL: AES256-SHA
				""";
		DeepVioletFactory.loadCipherMap(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		// Verify replacement: the custom map has only 2 ciphers
		assertEquals("STRONG", CipherSuiteUtil.getStrength("TLS_RSA_WITH_AES_128_CBC_SHA"));
		assertEquals("STRONG", CipherSuiteUtil.getStrength("TLS_RSA_WITH_AES_256_CBC_SHA"));
	}

	@Test
	public void testLoadCipherMapInvalidYamlThrows() {
		String yaml = "not: valid: yaml: [[[";
		assertThrows(DeepVioletException.class, () ->
				DeepVioletFactory.loadCipherMap(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
	}

	@Test
	public void testLoadCipherMapMissingKeyThrows() {
		String yaml = """
				metadata:
				  version: "1.0"
				some_other_key: []
				""";
		assertThrows(DeepVioletException.class, () ->
				DeepVioletFactory.loadCipherMap(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
	}

	@Test
	public void testResetCipherMap() throws Exception {
		// Load custom map with just 2 ciphers
		String yaml = """
				metadata:
				  version: "1.0"
				cipher_suites:
				  - id: "0x00,0x2F"
				    strength: WEAK
				    names:
				      IANA: TLS_RSA_WITH_AES_128_CBC_SHA
				      OpenSSL: AES128-SHA
				""";
		DeepVioletFactory.loadCipherMap(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));
		assertEquals("WEAK", CipherSuiteUtil.getStrength("TLS_RSA_WITH_AES_128_CBC_SHA"));

		// Reset — next access should re-init from classpath
		DeepVioletFactory.resetCipherMap();

		// Trigger re-init by loading from classpath
		assertFalse(CipherSuiteUtil.bCiphersInitialized);
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> loadCiphermap() {
		LoadSettings settings = LoadSettings.builder().build();
		Load load = new Load(settings);
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("ciphermap.yaml")) {
			assertNotNull(is, "ciphermap.yaml should be on classpath");
			return (Map<String, Object>) load.loadFromInputStream(is);
		} catch (Exception e) {
			fail("Failed to load ciphermap.yaml: " + e.getMessage());
			return null;
		}
	}
}
