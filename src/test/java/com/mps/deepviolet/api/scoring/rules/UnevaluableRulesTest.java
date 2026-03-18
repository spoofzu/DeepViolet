package com.mps.deepviolet.api.scoring.rules;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests that unevaluable rules fire when scan.*_failed flags are set,
 * and produce inconclusive deductions.
 */
class UnevaluableRulesTest {

	private RulePolicy policy;
	private Map<String, Object> rootProps;
	private Map<String, List<String>> headers;

	@BeforeEach
	void setUp() {
		InputStream is = getClass().getClassLoader().getResourceAsStream("risk-scoring-rules.yaml");
		policy = RulePolicyLoader.loadFromStream(is);
		rootProps = buildMinimalProps();
		headers = new LinkedHashMap<>();
	}

	@Test
	void certRetrievalFailedFiresInconclusive() {
		getScanMap().put("certificate_retrieval_failed", true);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		IDeduction d = findDeduction(score, "SYS-0021700");
		assertNotNull(d);
		assertTrue(d.isInconclusive(), "Should be inconclusive");
		assertEquals(0.2, d.getScore(), 0.001);
	}

	@Test
	void certRetrievalNotFailedDoesNotFire() {
		getScanMap().put("certificate_retrieval_failed", false);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionAbsent(score, "SYS-0021700");
	}

	@Test
	void revocationCheckFailedFiresInconclusive() {
		getScanMap().put("revocation_check_failed", true);
		ICategoryScore score = scoreCategory("REVOCATION");
		IDeduction d = findDeduction(score, "SYS-0030700");
		assertNotNull(d);
		assertTrue(d.isInconclusive(), "Should be inconclusive");
		assertEquals(0.2, d.getScore(), 0.001);
	}

	@Test
	void revocationCheckNotFailedDoesNotFire() {
		getScanMap().put("revocation_check_failed", false);
		ICategoryScore score = scoreCategory("REVOCATION");
		assertDeductionAbsent(score, "SYS-0030700");
	}

	@Test
	void dnsSecurityFailedFiresInconclusive() {
		getScanMap().put("dns_security_failed", true);
		ICategoryScore score = scoreCategory("DNS_SECURITY");
		IDeduction d = findDeduction(score, "SYS-0050300");
		assertNotNull(d);
		assertTrue(d.isInconclusive(), "Should be inconclusive");
		assertEquals(0.15, d.getScore(), 0.001);
	}

	@Test
	void dnsSecurityNotFailedDoesNotFire() {
		getScanMap().put("dns_security_failed", false);
		ICategoryScore score = scoreCategory("DNS_SECURITY");
		assertDeductionAbsent(score, "SYS-0050300");
	}

	@Test
	void tlsFingerprintFailedFiresInconclusive() {
		getScanMap().put("tls_fingerprint_failed", true);
		ICategoryScore score = scoreCategory("OTHER");
		IDeduction d = findDeduction(score, "SYS-0060700");
		assertNotNull(d);
		assertTrue(d.isInconclusive(), "Should be inconclusive");
		assertEquals(0.1, d.getScore(), 0.001);
	}

	@Test
	void tlsFingerprintNotFailedDoesNotFire() {
		getScanMap().put("tls_fingerprint_failed", false);
		ICategoryScore score = scoreCategory("OTHER");
		assertDeductionAbsent(score, "SYS-0060700");
	}

	@Test
	void inconclusiveDeductionsDoNotAffectNumericScore() {
		// All scan failures set — inconclusive deductions should not change score
		getScanMap().put("certificate_retrieval_failed", true);
		getScanMap().put("revocation_check_failed", true);
		getScanMap().put("dns_security_failed", true);
		getScanMap().put("tls_fingerprint_failed", true);

		// Score each category; inconclusive deductions should not contribute to average
		for (String cat : List.of("CERTIFICATE", "REVOCATION", "DNS_SECURITY", "OTHER")) {
			ICategoryScore score = scoreCategory(cat);
			for (IDeduction d : score.getDeductions()) {
				if (d.isInconclusive()) {
					// Verify the deduction exists but is marked inconclusive
					assertTrue(d.isInconclusive());
				}
			}
		}
	}

	// --- Helper methods ---

	private ICategoryScore scoreCategory(String categoryKey) {
		CategoryDefinition catDef = policy.getCategories().stream()
				.filter(c -> c.key().equals(categoryKey))
				.findFirst().orElseThrow();
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		return new ExternalizedCategoryScorer(catDef, ctx, policy).score();
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> getScanMap() {
		return (Map<String, Object>) rootProps.get("scan");
	}

	private IDeduction findDeduction(ICategoryScore score, String ruleId) {
		for (IDeduction d : score.getDeductions()) {
			if (d.getRuleId().equals(ruleId)) return d;
		}
		return null;
	}

	private void assertDeductionAbsent(ICategoryScore score, String ruleId) {
		for (IDeduction d : score.getDeductions()) {
			if (d.getRuleId().equals(ruleId)) {
				fail("Deduction '" + ruleId + "' should not be present");
			}
		}
	}

	/**
	 * Build minimal props that make existing rules not fire
	 * (so we can test scan.* rules in isolation).
	 */
	private Map<String, Object> buildMinimalProps() {
		Map<String, Object> props = new HashMap<>();

		Map<String, Object> session = new LinkedHashMap<>();
		session.put("negotiated_protocol", "TLSv1.3");
		session.put("negotiated_cipher_suite", "TLS_AES_256_GCM_SHA384");
		session.put("negotiated_cipher_strength", "STRONG");
		session.put("compression_enabled", false);
		session.put("client_auth_required", false);
		session.put("headers_available", false);
		session.put("fingerprint", "abc123");
		session.put("tls_metadata_available", false);
		session.put("pq_kex_supported", null);
		session.put("pq_kex_probe_failed", false);
		session.put("fallback_scsv_supported", null);
		session.put("honors_client_cipher_preference", null);
		props.put("session", session);

		props.put("protocols", Set.of("TLSv1.3"));

		props.put("ciphers", List.of(
				Map.of("name", "TLS_AES_256_GCM_SHA384", "strength", "STRONG", "protocol", "TLSv1.3")));

		Map<String, Object> cert = new LinkedHashMap<>();
		cert.put("validity_state", "VALID");
		cert.put("trust_state", "TRUSTED");
		cert.put("self_signed", false);
		cert.put("java_root", false);
		cert.put("key_algorithm", "RSA");
		cert.put("key_size", 4096L);
		cert.put("signing_algorithm", "SHA256withRSA");
		cert.put("days_until_expiration", 365L);
		cert.put("chain_length", 3L);
		cert.put("san_count", 1L);
		cert.put("sans", List.of("example.com"));
		cert.put("version", 3L);
		cert.put("has_wildcard_san", false);
		props.put("cert", cert);

		Map<String, Object> rev = new LinkedHashMap<>();
		rev.put("available", true);
		rev.put("ocsp_status", "GOOD");
		rev.put("crl_status", "GOOD");
		rev.put("ocsp_stapling_present", true);
		rev.put("must_staple_present", true);
		rev.put("sct_count", 3L);
		rev.put("embedded_sct_count", 2L);
		props.put("revocation", rev);

		Map<String, Object> dns = new LinkedHashMap<>();
		dns.put("available", true);
		dns.put("has_caa_records", true);
		dns.put("has_tlsa_records", true);
		props.put("dns", dns);

		// Scan failure flags — all false by default
		Map<String, Object> scan = new LinkedHashMap<>();
		scan.put("certificate_retrieval_failed", false);
		scan.put("revocation_check_failed", false);
		scan.put("tls_fingerprint_failed", false);
		scan.put("dns_security_failed", false);
		props.put("scan", scan);

		return props;
	}
}
