package com.mps.deepviolet.api.scoring.rules;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for expression evaluation, including null safety and type coercion.
 */
class RuleExpressionEvaluatorTest {

	private Map<String, Object> rootProps;
	private Map<String, List<String>> headers;

	@BeforeEach
	void setUp() {
		rootProps = new HashMap<>();
		headers = new LinkedHashMap<>();

		// session properties
		Map<String, Object> session = new LinkedHashMap<>();
		session.put("negotiated_protocol", "TLSv1.3");
		session.put("negotiated_cipher_suite", "TLS_AES_256_GCM_SHA384");
		session.put("negotiated_cipher_strength", "STRONG");
		session.put("compression_enabled", false);
		session.put("client_auth_required", false);
		session.put("headers_available", true);
		session.put("fingerprint", "abc123");
		rootProps.put("session", session);

		// protocols
		rootProps.put("protocols", Set.of("TLSv1.2", "TLSv1.3"));

		// ciphers
		Map<String, Object> cipher1 = Map.of("name", "TLS_AES_256_GCM_SHA384", "strength", "STRONG", "protocol", "TLSv1.3");
		Map<String, Object> cipher2 = Map.of("name", "TLS_RSA_WITH_AES_128_CBC_SHA", "strength", "WEAK", "protocol", "TLSv1.2");
		rootProps.put("ciphers", List.of(cipher1, cipher2));

		// cert properties
		Map<String, Object> cert = new LinkedHashMap<>();
		cert.put("validity_state", "VALID");
		cert.put("trust_state", "TRUSTED");
		cert.put("self_signed", false);
		cert.put("java_root", false);
		cert.put("key_algorithm", "RSA");
		cert.put("key_size", 2048L);
		cert.put("key_curve", null);
		cert.put("signing_algorithm", "SHA256withRSA");
		cert.put("days_until_expiration", 365L);
		cert.put("chain_length", 3L);
		cert.put("san_count", 2L);
		cert.put("sans", List.of("example.com", "www.example.com"));
		cert.put("version", 3L);
		rootProps.put("cert", cert);

		// revocation properties
		Map<String, Object> rev = new LinkedHashMap<>();
		rev.put("available", true);
		rev.put("ocsp_status", "GOOD");
		rev.put("crl_status", "GOOD");
		rev.put("ocsp_stapling_present", true);
		rev.put("must_staple_present", false);
		rev.put("sct_count", 3L);
		rev.put("embedded_sct_count", 2L);
		rootProps.put("revocation", rev);

		// headers
		headers.put("Strict-Transport-Security", List.of("max-age=31536000; includeSubDomains"));
		headers.put("X-Content-Type-Options", List.of("nosniff"));
	}

	private boolean eval(String expression) {
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		RuleExpressionEvaluator evaluator = new RuleExpressionEvaluator(ctx);
		return evaluator.evaluateBoolean(RuleExpressionParser.parse(expression));
	}

	// --- Basic comparisons ---

	@Test
	void testStringEquals() {
		assertTrue(eval("cert.key_algorithm == \"RSA\""));
		assertFalse(eval("cert.key_algorithm == \"EC\""));
	}

	@Test
	void testStringNotEquals() {
		assertTrue(eval("cert.key_algorithm != \"EC\""));
		assertFalse(eval("cert.key_algorithm != \"RSA\""));
	}

	@Test
	void testNumericLessThan() {
		assertFalse(eval("cert.key_size < 2048"));
		assertTrue(eval("cert.key_size < 4096"));
	}

	@Test
	void testNumericGreaterThanOrEqual() {
		assertTrue(eval("cert.key_size >= 2048"));
		assertTrue(eval("cert.key_size >= 1024"));
		assertFalse(eval("cert.key_size >= 4096"));
	}

	@Test
	void testNumericEquals() {
		assertTrue(eval("cert.key_size == 2048"));
		assertFalse(eval("cert.key_size == 1024"));
	}

	@Test
	void testBooleanEquals() {
		assertFalse(eval("session.compression_enabled == true"));
		assertTrue(eval("session.compression_enabled == false"));
	}

	// --- Null safety ---

	@Test
	void testNullEqualsNull() {
		assertTrue(eval("cert.key_curve == null"));
	}

	@Test
	void testNullNotEqualsNull() {
		assertFalse(eval("cert.key_curve != null"));
	}

	@Test
	void testNonNullNotEqualsNull() {
		assertTrue(eval("cert.key_algorithm != null"));
	}

	@Test
	void testNullLessThan() {
		// null < anything → false
		assertFalse(eval("cert.key_curve < 100"));
	}

	@Test
	void testMissingPropertyIsNull() {
		assertTrue(eval("cert.nonexistent_property == null"));
	}

	// --- Contains ---

	@Test
	void testSetContains() {
		assertTrue(eval("protocols contains \"TLSv1.3\""));
		assertFalse(eval("protocols contains \"SSLv2\""));
	}

	@Test
	void testSetNotContains() {
		assertTrue(eval("protocols not contains \"SSLv2\""));
		assertFalse(eval("protocols not contains \"TLSv1.3\""));
	}

	@Test
	void testNullCollectionContains() {
		// null collection → false for contains
		Map<String, Object> props = new HashMap<>(rootProps);
		props.put("protocols", null);
		RuleContext ctx = RuleContext.fromMaps(props, headers);
		RuleExpressionEvaluator evaluator = new RuleExpressionEvaluator(ctx);
		assertFalse(evaluator.evaluateBoolean(RuleExpressionParser.parse("protocols contains \"TLSv1.3\"")));
	}

	@Test
	void testNullCollectionNotContains() {
		// null collection → true for not contains
		Map<String, Object> props = new HashMap<>(rootProps);
		props.put("protocols", null);
		RuleContext ctx = RuleContext.fromMaps(props, headers);
		RuleExpressionEvaluator evaluator = new RuleExpressionEvaluator(ctx);
		assertTrue(evaluator.evaluateBoolean(RuleExpressionParser.parse("protocols not contains \"TLSv1.3\"")));
	}

	// --- And / Or / Not ---

	@Test
	void testAndBothTrue() {
		assertTrue(eval("cert.key_algorithm == \"RSA\" and cert.key_size >= 2048"));
	}

	@Test
	void testAndOneFalse() {
		assertFalse(eval("cert.key_algorithm == \"RSA\" and cert.key_size < 2048"));
	}

	@Test
	void testOrOneTrue() {
		assertTrue(eval("cert.key_algorithm == \"EC\" or cert.key_algorithm == \"RSA\""));
	}

	@Test
	void testOrBothFalse() {
		assertFalse(eval("cert.key_algorithm == \"EC\" or cert.key_algorithm == \"DSA\""));
	}

	@Test
	void testNotTrue() {
		assertTrue(eval("not session.compression_enabled"));
	}

	@Test
	void testNotFalse() {
		assertFalse(eval("not session.headers_available"));
	}

	// --- Functions ---

	@Test
	void testCountFiltered() {
		assertTrue(eval("count(ciphers, strength == \"WEAK\") >= 1"));
		assertTrue(eval("count(ciphers, strength == \"STRONG\") == 1"));
		assertTrue(eval("count(ciphers, strength == \"CLEAR\") == 0"));
	}

	@Test
	void testCountFilteredContains() {
		// cipher2 name contains "CBC"
		assertTrue(eval("count(ciphers, name contains \"CBC\") == 1"));
		assertTrue(eval("count(ciphers, name contains \"GCM\") == 1"));
		assertTrue(eval("count(ciphers, name contains \"RC4\") == 0"));
	}

	@Test
	void testCountFilteredNotContains() {
		// Both ciphers don't contain "RC4"
		assertTrue(eval("count(ciphers, name not contains \"RC4\") == 2"));
		// Only cipher1 does not contain "CBC"
		assertTrue(eval("count(ciphers, name not contains \"CBC\") == 1"));
	}

	@Test
	void testCountFilteredStartsWith() {
		// Both ciphers start with "TLS_"
		assertTrue(eval("count(ciphers, name starts_with \"TLS_\") == 2"));
		assertTrue(eval("count(ciphers, name starts_with \"TLS_AES\") == 1"));
		assertTrue(eval("count(ciphers, name starts_with \"SSL_\") == 0"));
	}

	@Test
	void testCountUnfiltered() {
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		RuleExpressionEvaluator evaluator = new RuleExpressionEvaluator(ctx);
		Object result = evaluator.evaluate(RuleExpressionParser.parse("count(ciphers)"));
		assertEquals(2L, result);
	}

	@Test
	void testHeaderFunction() {
		assertTrue(eval("header(\"Strict-Transport-Security\") != null"));
		assertTrue(eval("header(\"X-Frame-Options\") == null"));
	}

	@Test
	void testHeaderPresentFunction() {
		assertTrue(eval("header_present(\"X-Content-Type-Options\")"));
		assertFalse(eval("header_present(\"Content-Security-Policy\")"));
	}

	@Test
	void testParseMaxAge() {
		assertTrue(eval("parse_max_age(header(\"Strict-Transport-Security\")) >= 31536000"));
		assertTrue(eval("parse_max_age(header(\"Strict-Transport-Security\")) == 31536000"));
	}

	@Test
	void testUpperFunction() {
		assertTrue(eval("contains(upper(cert.signing_algorithm), \"SHA256\")"));
	}

	@Test
	void testLowerFunction() {
		assertTrue(eval("contains(lower(cert.signing_algorithm), \"sha256\")"));
	}

	@Test
	void testStartsWithFunction() {
		assertTrue(eval("starts_with(cert.signing_algorithm, \"SHA256\")"));
		assertFalse(eval("starts_with(cert.signing_algorithm, \"MD5\")"));
	}

	// --- Complex real-world rules ---

	@Test
	void testCertificateExpirationRule() {
		// "expires in less than 30 days" — with 365 days remaining, should be false
		assertFalse(eval("cert.days_until_expiration >= 0 and cert.days_until_expiration < 30"));
	}

	@Test
	void testCertificateExpirationRuleSoon() {
		Map<String, Object> cert = new LinkedHashMap<>((Map<String, Object>) rootProps.get("cert"));
		cert.put("days_until_expiration", 15L);
		rootProps.put("cert", cert);
		assertTrue(eval("cert.days_until_expiration >= 0 and cert.days_until_expiration < 30"));
	}

	@Test
	void testHeaderMissingRule() {
		assertTrue(eval("session.headers_available and header(\"X-Frame-Options\") == null"));
	}

	@Test
	void testHeaderMissingWhenHeadersUnavailable() {
		Map<String, Object> session = new LinkedHashMap<>((Map<String, Object>) rootProps.get("session"));
		session.put("headers_available", false);
		rootProps.put("session", session);
		assertTrue(eval("not session.headers_available"));
	}

	@Test
	void testRevocationBothErrors() {
		Map<String, Object> rev = new LinkedHashMap<>((Map<String, Object>) rootProps.get("revocation"));
		rev.put("ocsp_status", "ERROR");
		rev.put("crl_status", "ERROR");
		rootProps.put("revocation", rev);
		assertTrue(eval("revocation.ocsp_status == \"ERROR\" and revocation.crl_status == \"ERROR\""));
	}

	@Test
	void testRevocationNotAvailable() {
		Map<String, Object> rev = new LinkedHashMap<>();
		rev.put("available", false);
		rootProps.put("revocation", rev);
		assertTrue(eval("not revocation.available"));
	}

	@Test
	void testSelfSignedNotJavaRoot() {
		Map<String, Object> cert = new LinkedHashMap<>((Map<String, Object>) rootProps.get("cert"));
		cert.put("self_signed", true);
		cert.put("java_root", false);
		rootProps.put("cert", cert);
		assertTrue(eval("cert.self_signed == true and cert.java_root == false"));
	}

	@Test
	void testWeakSignatureAlgorithm() {
		Map<String, Object> cert = new LinkedHashMap<>((Map<String, Object>) rootProps.get("cert"));
		cert.put("signing_algorithm", "SHA1withRSA");
		rootProps.put("cert", cert);
		assertTrue(eval(
				"contains(upper(cert.signing_algorithm), \"SHA1\") or contains(upper(cert.signing_algorithm), \"SHA-1\") or contains(upper(cert.signing_algorithm), \"MD5\")"));
	}

	@Test
	void testStrongSignatureAlgorithm() {
		assertFalse(eval(
				"contains(upper(cert.signing_algorithm), \"SHA1\") or contains(upper(cert.signing_algorithm), \"SHA-1\") or contains(upper(cert.signing_algorithm), \"MD5\")"));
	}
}
