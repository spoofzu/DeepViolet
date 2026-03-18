package com.mps.deepviolet.api.scoring.rules;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.scoring.RiskScorer;

import org.junit.jupiter.api.Test;

/**
 * Tests for RuleContext serialization round-trip and offline scoring.
 */
public class RuleContextSerializationTest {

	@Test
	void testRoundTrip() {
		// Build a context with representative data
		Map<String, Object> props = new LinkedHashMap<>();

		Map<String, Object> sessionProps = new LinkedHashMap<>();
		sessionProps.put("negotiated_protocol", "TLSv1.3");
		sessionProps.put("negotiated_cipher_suite", "TLS_AES_256_GCM_SHA384");
		sessionProps.put("compression_enabled", false);
		sessionProps.put("fingerprint", "abc123");
		props.put("session", sessionProps);

		Set<String> protocols = new HashSet<>();
		protocols.add("TLSv1.2");
		protocols.add("TLSv1.3");
		props.put("protocols", protocols);

		Map<String, Object> certProps = new LinkedHashMap<>();
		certProps.put("key_size", 2048L);
		certProps.put("self_signed", false);
		props.put("cert", certProps);

		Map<String, List<String>> headers = new HashMap<>();
		headers.put("Strict-Transport-Security", List.of("max-age=31536000"));

		RuleContext original = RuleContext.fromMaps(props, headers);

		// Serialize
		Map<String, Object> serialized = original.toSerializableMap();
		assertNotNull(serialized);
		assertEquals("1.0", serialized.get("context_version"));
		assertNotNull(serialized.get("properties"));

		// Deserialize
		RuleContext restored = RuleContext.fromSerializableMap(serialized);

		// Verify all properties resolve identically
		assertEquals(
				original.resolve(List.of("session", "negotiated_protocol")),
				restored.resolve(List.of("session", "negotiated_protocol")));
		assertEquals(
				original.resolve(List.of("session", "fingerprint")),
				restored.resolve(List.of("session", "fingerprint")));
		assertEquals(
				original.resolve(List.of("cert", "key_size")),
				restored.resolve(List.of("cert", "key_size")));
		assertEquals(
				original.resolve(List.of("cert", "self_signed")),
				restored.resolve(List.of("cert", "self_signed")));

		// Headers survive
		assertEquals("max-age=31536000", restored.getHeader("Strict-Transport-Security"));
	}

	@Test
	void testProtocolSetToListRoundTrip() {
		Map<String, Object> props = new LinkedHashMap<>();
		Set<String> protocols = new HashSet<>();
		protocols.add("TLSv1.2");
		protocols.add("TLSv1.3");
		props.put("protocols", protocols);

		RuleContext original = RuleContext.fromMaps(props, null);

		// Verify original has Set
		Object originalProtocols = original.resolve(List.of("protocols"));
		assertTrue(originalProtocols instanceof Set, "Original protocols should be a Set");

		// Serialize and deserialize
		Map<String, Object> serialized = original.toSerializableMap();
		RuleContext restored = RuleContext.fromSerializableMap(serialized);

		// After round-trip, protocols should be a List (JSON doesn't have Set)
		Object restoredProtocols = restored.resolve(List.of("protocols"));
		assertTrue(restoredProtocols instanceof List, "Restored protocols should be a List");

		// Both should contain the same elements
		assertTrue(((java.util.Collection<?>) restoredProtocols).contains("TLSv1.2"));
		assertTrue(((java.util.Collection<?>) restoredProtocols).contains("TLSv1.3"));
	}

	@Test
	void testOfflineScoring() throws Exception {
		// Build a minimal context
		Map<String, Object> props = new LinkedHashMap<>();

		Map<String, Object> sessionProps = new LinkedHashMap<>();
		sessionProps.put("negotiated_protocol", "TLSv1.3");
		sessionProps.put("negotiated_cipher_suite", "TLS_AES_256_GCM_SHA384");
		sessionProps.put("compression_enabled", false);
		sessionProps.put("headers_available", true);
		sessionProps.put("tls_metadata_available", false);
		sessionProps.put("fallback_scsv_supported", true);
		sessionProps.put("negotiated_cipher_strength", "STRONG");
		props.put("session", sessionProps);

		Set<String> protocols = new HashSet<>();
		protocols.add("TLSv1.2");
		protocols.add("TLSv1.3");
		props.put("protocols", protocols);

		Map<String, Object> certProps = new LinkedHashMap<>();
		certProps.put("validity_state", "VALID");
		certProps.put("trust_state", "TRUSTED");
		certProps.put("self_signed", false);
		certProps.put("java_root", false);
		certProps.put("key_algorithm", "RSA");
		certProps.put("key_size", 2048L);
		certProps.put("signing_algorithm", "SHA256withRSA");
		certProps.put("days_until_expiration", 180L);
		certProps.put("chain_length", 3L);
		certProps.put("san_count", 1L);
		certProps.put("has_wildcard_san", false);
		certProps.put("version", 3L);
		props.put("cert", certProps);

		Map<String, Object> revProps = new LinkedHashMap<>();
		revProps.put("available", true);
		revProps.put("ocsp_status", "GOOD");
		revProps.put("crl_status", "GOOD");
		revProps.put("ocsp_stapling_present", true);
		revProps.put("must_staple_present", false);
		revProps.put("sct_count", 3L);
		revProps.put("embedded_sct_count", 2L);
		props.put("revocation", revProps);

		Map<String, Object> dnsProps = new LinkedHashMap<>();
		dnsProps.put("available", false);
		props.put("dns", dnsProps);

		Map<String, List<String>> headers = new HashMap<>();
		headers.put("Strict-Transport-Security", List.of("max-age=31536000"));

		RuleContext context = RuleContext.fromMaps(props, headers);

		// Load system policy
		InputStream is = getClass().getClassLoader()
				.getResourceAsStream("risk-scoring-rules.yaml");
		RulePolicy policy = RulePolicyLoader.loadFromStream(is);

		// Score offline
		IRiskScore score = RiskScorer.computeScore(context, "https://example.com", policy);

		assertNotNull(score);
		assertTrue(score.getTotalScore() >= 0 && score.getTotalScore() <= 100,
				"Score should be 0-100, was: " + score.getTotalScore());
		assertNotNull(score.getLetterGrade());
		assertNotNull(score.getRiskLevel());
		assertTrue(score.getCategoryScores().length > 0);
	}

	@Test
	void testWarningsRoundTrip() {
		Map<String, Object> props = new LinkedHashMap<>();
		props.put("session", new LinkedHashMap<>());

		RuleContext original = RuleContext.fromMaps(props, null);

		// Serialize — should have empty warnings
		Map<String, Object> serialized = original.toSerializableMap();
		@SuppressWarnings("unchecked")
		List<String> warnings = (List<String>) serialized.get("warnings");
		assertNotNull(warnings);
		assertTrue(warnings.isEmpty());

		// Add warnings and re-serialize
		// We can't add warnings directly, but we can test via fromSerializableMap
		Map<String, Object> withWarnings = new LinkedHashMap<>(serialized);
		withWarnings.put("warnings", List.of("test warning 1", "test warning 2"));

		RuleContext restored = RuleContext.fromSerializableMap(withWarnings);
		List<String> restoredWarnings = restored.getWarnings();
		assertEquals(2, restoredWarnings.size());
		assertEquals("test warning 1", restoredWarnings.get(0));
		assertEquals("test warning 2", restoredWarnings.get(1));
	}

	@Test
	void testPqVariablesRoundTrip() {
		Map<String, Object> props = new LinkedHashMap<>();

		Map<String, Object> sessionProps = new LinkedHashMap<>();
		sessionProps.put("negotiated_group", "X25519MLKEM768");
		sessionProps.put("negotiated_group_pq", true);
		sessionProps.put("pq_kex_supported", false);
		sessionProps.put("pq_kex_groups", "X25519MLKEM768, SecP256r1MLKEM768");
		sessionProps.put("pq_kex_preferred", true);
		sessionProps.put("pq_preferred_group", "X25519MLKEM768");
		props.put("session", sessionProps);

		RuleContext original = RuleContext.fromMaps(props, null);

		Map<String, Object> serialized = original.toSerializableMap();
		RuleContext restored = RuleContext.fromSerializableMap(serialized);

		assertEquals("X25519MLKEM768",
				restored.resolve(List.of("session", "negotiated_group")));
		assertEquals(true,
				restored.resolve(List.of("session", "negotiated_group_pq")));
		assertEquals(false,
				restored.resolve(List.of("session", "pq_kex_supported")));
		assertEquals("X25519MLKEM768, SecP256r1MLKEM768",
				restored.resolve(List.of("session", "pq_kex_groups")));
		assertEquals(true,
				restored.resolve(List.of("session", "pq_kex_preferred")));
		assertEquals("X25519MLKEM768",
				restored.resolve(List.of("session", "pq_preferred_group")));
	}

	@Test
	void testNullHeadersRoundTrip() {
		Map<String, Object> props = new LinkedHashMap<>();
		props.put("session", new LinkedHashMap<>());

		RuleContext original = RuleContext.fromMaps(props, null);
		Map<String, Object> serialized = original.toSerializableMap();
		assertNull(serialized.get("headers"));

		RuleContext restored = RuleContext.fromSerializableMap(serialized);
		assertNull(restored.getHeader("anything"));
	}
}
