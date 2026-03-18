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
import com.mps.deepviolet.api.IRiskScore.IScoringDiagnostic;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for ExternalizedCategoryScorer using the bundled YAML rules.
 */
class ExternalizedCategoryScorerTest {

	private RulePolicy policy;
	private Map<String, Object> rootProps;
	private Map<String, List<String>> headers;

	@BeforeEach
	void setUp() {
		InputStream is = getClass().getClassLoader().getResourceAsStream("risk-scoring-rules.yaml");
		policy = RulePolicyLoader.loadFromStream(is);
		rootProps = buildPerfectProps();
		headers = buildPerfectHeaders();
	}

	// --- Protocol tests ---

	@Test
	void testProtocolsPerfectScore() {
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertEquals(100, score.getScore());
		// INFO rules SYS-0001300 (pq_kex_available) and SYS-0001400 (pq_kex_preferred) fire — score 0.0
		assertEquals(2, score.getDeductions().length);
		assertDeductionPresent(score, "SYS-0001300");
		assertDeductionPresent(score, "SYS-0001400");
		assertEquals(0.0, findDeduction(score, "SYS-0001300").getScore(), 0.001);
		assertEquals(0.0, findDeduction(score, "SYS-0001400").getScore(), 0.001);
	}

	@Test
	void testProtocolsSSLv2Detected() {
		getSet("protocols").add("SSLv2");
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertTrue(score.getScore() < 100);
		assertDeductionPresent(score, "SYS-0000100");
	}

	@Test
	void testProtocolsTLS13Missing() {
		rootProps.put("protocols", Set.of("TLSv1.2"));
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0000500");
	}

	@Test
	void testProtocolsInsecureRenegotiation() {
		getSessionMap().put("negotiated_protocol", "TLSv1.2");
		getSessionMap().put("renegotiation_info_present", false);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0000700");
	}

	@Test
	void testProtocolsInsecureRenegotiationSkippedForTLS13() {
		getSessionMap().put("negotiated_protocol", "TLSv1.3");
		getSessionMap().put("renegotiation_info_present", false);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionAbsent(score, "SYS-0000700");
	}

	@Test
	void testProtocolsInsecureRenegotiationInconclusive() {
		getSessionMap().put("tls_metadata_available", false);
		getSessionMap().remove("renegotiation_info_present");
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0000700");
		assertTrue(findDeduction(score, "SYS-0000700").isInconclusive());
	}

	@Test
	void testProtocolsEarlyDataAccepted() {
		getSessionMap().put("early_data_accepted", true);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0000800");
	}

	@Test
	void testProtocolsNoALPN() {
		getSessionMap().put("alpn_negotiated", null);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0000900");
	}

	@Test
	void testProtocolsNoFallbackSCSV() {
		getSessionMap().put("fallback_scsv_supported", false);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001000");
	}

	@Test
	void testProtocolsFallbackSCSVInconclusive() {
		getSessionMap().put("fallback_scsv_supported", null);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001000");
		assertTrue(findDeduction(score, "SYS-0001000").isInconclusive());
	}

	@Test
	void testProtocolsTLS10Detected() {
		getSet("protocols").add("TLSv1.0");
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0000300");
	}

	// --- Post-Quantum rules tests ---

	@Test
	void testPqKexPreferredFalse_RuleFires() {
		// pq_kex_preferred=false → SYS-0001100 fires (server prefers classical)
		getSessionMap().put("pq_kex_preferred", false);
		getSessionMap().put("pq_kex_supported", true);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001100");
		assertFalse(findDeduction(score, "SYS-0001100").isInconclusive());
	}

	@Test
	void testPqKexPreferredTrue_RuleDoesNotFire() {
		// pq_kex_preferred=true → SYS-0001100 does NOT fire
		getSessionMap().put("pq_kex_preferred", true);
		getSessionMap().put("pq_kex_supported", true);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionAbsent(score, "SYS-0001100");
		assertDeductionAbsent(score, "SYS-0001200");
		assertDeductionPresent(score, "SYS-0001300");
	}

	@Test
	void testPqKexPreferredNull_SupportedTrue_Inconclusive() {
		// pq_kex_supported=true, pq_kex_preferred=null → SYS-0001100 inconclusive
		getSessionMap().put("pq_kex_supported", true);
		getSessionMap().put("pq_kex_preferred", null);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001100");
		assertTrue(findDeduction(score, "SYS-0001100").isInconclusive());
	}

	@Test
	void testPqKexPreferredNull_SupportedFalse_NoFire() {
		// pq_kex_supported=false, pq_kex_preferred=null → SYS-0001100 does NOT fire
		// (pq_kex_preferred==null alone is ambiguous; without pq_kex_supported==true, skip)
		getSessionMap().put("pq_kex_supported", false);
		getSessionMap().put("pq_kex_preferred", null);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionAbsent(score, "SYS-0001100");
		// SYS-0001200 fires instead (no PQ support)
		assertDeductionPresent(score, "SYS-0001200");
	}

	@Test
	void testPqKexNotAvailable_Only1200Fires() {
		// pq_kex_supported=false, pq_kex_preferred=false → only SYS-0001200 fires
		// SYS-0001100 requires pq_kex_supported==true, so it does NOT fire here
		getSessionMap().put("pq_kex_supported", false);
		getSessionMap().put("pq_kex_preferred", false);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionAbsent(score, "SYS-0001100");
		assertDeductionPresent(score, "SYS-0001200");
	}

	@Test
	void testPqKexAvailableInfoRule() {
		// pq_kex_supported=true → SYS-0001300 fires with severity INFO, score 0.0
		getSessionMap().put("pq_kex_supported", true);
		getSessionMap().put("pq_kex_groups", "X25519MLKEM768, SecP256r1MLKEM768");
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001300");
		IDeduction d = findDeduction(score, "SYS-0001300");
		assertEquals(0.0, d.getScore(), 0.001);
		assertEquals("INFO", d.getSeverity());
		assertTrue(d.getDescription().contains("X25519MLKEM768"));
		assertTrue(d.getDescription().contains("SecP256r1MLKEM768"));
	}

	@Test
	void testPqKexSupportedNull() {
		// pq_kex_supported=null → rule #2 inconclusive
		getSessionMap().put("pq_kex_supported", null);
		getSessionMap().put("pq_kex_preferred", null);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001200");
		assertTrue(findDeduction(score, "SYS-0001200").isInconclusive());
	}

	@Test
	void testPqKexProbeFailed() {
		// TLS 1.3 server but PQ probes failed after retries → SYS-0001500 fires
		getSessionMap().put("pq_kex_supported", null);
		getSessionMap().put("pq_kex_preferred", null);
		getSessionMap().put("pq_kex_probe_failed", true);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionPresent(score, "SYS-0001500");
		assertEquals(0.15, findDeduction(score, "SYS-0001500").getScore(), 0.001);
	}

	@Test
	void testPqKexProbeNotFailed() {
		// PQ probes succeeded → SYS-0001500 does NOT fire
		getSessionMap().put("pq_kex_probe_failed", false);
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertDeductionAbsent(score, "SYS-0001500");
	}

	// --- Cipher Suite tests ---

	@Test
	void testCipherSuitesPerfectScore() {
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertEquals(100, score.getScore());
	}

	@Test
	void testCipherSuitesWeakCiphersDetected() {
		// Add 6 weak ciphers
		var ciphers = getCipherList();
		for (int i = 0; i < 6; i++) {
			ciphers.add(Map.of("name", "WEAK_CIPHER_" + i, "strength", "WEAK", "protocol", "TLSv1.2"));
		}
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0010200");
	}

	@Test
	void testCipherSuitesSomeWeakCiphers() {
		var ciphers = getCipherList();
		ciphers.add(Map.of("name", "WEAK_1", "strength", "WEAK", "protocol", "TLSv1.2"));
		ciphers.add(Map.of("name", "WEAK_2", "strength", "WEAK", "protocol", "TLSv1.2"));
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0010300");
		assertDeductionAbsent(score, "SYS-0010200");
	}

	@Test
	void testCipherSuitesNegotiatedWeak() {
		getSessionMap().put("negotiated_cipher_strength", "WEAK");
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0010500");
	}

	// --- Certificate tests ---

	@Test
	void testCertificatePerfectScore() {
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertEquals(100, score.getScore());
	}

	@Test
	void testCertificateExpired() {
		getCertMap().put("validity_state", "EXPIRED");
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020100");
	}

	@Test
	void testCertificateUntrusted() {
		getCertMap().put("trust_state", "UNTRUSTED");
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020300");
	}

	@Test
	void testCertificateRSAKeyTooSmall() {
		getCertMap().put("key_algorithm", "RSA");
		getCertMap().put("key_size", 1024L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020600");
	}

	@Test
	void testCertificateECKeyTooSmall() {
		getCertMap().put("key_algorithm", "EC");
		getCertMap().put("key_size", 128L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020700");
	}

	@Test
	void testCertificateWeakSigAlgo() {
		getCertMap().put("signing_algorithm", "SHA1withRSA");
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020800");
	}

	@Test
	void testCertificateExpiresSoon30() {
		getCertMap().put("days_until_expiration", 15L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020900");
	}

	@Test
	void testCertificateExpiresSoon90() {
		getCertMap().put("days_until_expiration", 45L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021000");
		assertDeductionAbsent(score, "SYS-0020900");
	}

	@Test
	void testCertificateSelfSigned() {
		getCertMap().put("self_signed", true);
		getCertMap().put("java_root", false);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0020500");
	}

	@Test
	void testCertificateSelfSignedJavaRoot() {
		getCertMap().put("self_signed", true);
		getCertMap().put("java_root", true);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionAbsent(score, "SYS-0020500");
	}

	@Test
	void testCertificateShortChain() {
		getCertMap().put("chain_length", 1L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021100");
	}

	// --- Revocation tests ---

	@Test
	void testRevocationPerfectScore() {
		ICategoryScore score = scoreCategory("REVOCATION");
		assertEquals(100, score.getScore());
	}

	@Test
	void testRevocationNotAvailableInconclusive() {
		Map<String, Object> rev = new LinkedHashMap<>();
		rev.put("available", false);
		rootProps.put("revocation", rev);
		ICategoryScore score = scoreCategory("REVOCATION");
		// Should have inconclusive deductions for no_ocsp_stapling, no_must_staple, no_scts
		long inconclusiveCount = 0;
		for (IDeduction d : score.getDeductions()) {
			if (d.isInconclusive()) inconclusiveCount++;
		}
		assertTrue(inconclusiveCount >= 3);
	}

	@Test
	void testRevocationBothErrors() {
		getRevMap().put("ocsp_status", "ERROR");
		getRevMap().put("crl_status", "ERROR");
		ICategoryScore score = scoreCategory("REVOCATION");
		assertDeductionPresent(score, "SYS-0030600");
		IDeduction d = findDeduction(score, "SYS-0030600");
		assertTrue(d.isInconclusive());
	}

	// --- Security Headers tests ---

	@Test
	void testSecurityHeadersPerfectScore() {
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertEquals(100, score.getScore());
	}

	@Test
	void testSecurityHeadersUnavailableInconclusive() {
		getSessionMap().put("headers_available", false);
		headers = null;
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		long inconclusiveCount = 0;
		for (IDeduction d : score.getDeductions()) {
			if (d.isInconclusive()) inconclusiveCount++;
		}
		assertTrue(inconclusiveCount >= 4); // no_hsts + no_content_type_options + no_frame_options + no_csp
	}

	@Test
	void testSecurityHeadersHSTSMissing() {
		headers.remove("Strict-Transport-Security");
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertDeductionPresent(score, "SYS-0040100");
		assertFalse(findDeduction(score, "SYS-0040100").isInconclusive());
	}

	@Test
	void testSecurityHeadersHSTSShortMaxAge() {
		headers.put("Strict-Transport-Security", List.of("max-age=3600"));
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertDeductionPresent(score, "SYS-0040200");
	}

	// --- Other tests ---

	@Test
	void testOtherPerfectScore() {
		ICategoryScore score = scoreCategory("OTHER");
		assertEquals(100, score.getScore());
	}

	@Test
	void testOtherCompressionEnabled() {
		getSessionMap().put("compression_enabled", true);
		ICategoryScore score = scoreCategory("OTHER");
		assertDeductionPresent(score, "SYS-0060100");
	}

	@Test
	void testOtherFingerprintUnavailable() {
		getSessionMap().put("fingerprint", null);
		ICategoryScore score = scoreCategory("OTHER");
		assertDeductionPresent(score, "SYS-0060300");
		assertTrue(findDeduction(score, "SYS-0060300").isInconclusive());
	}

	@Test
	void testOtherHighSANExposure() {
		getCertMap().put("san_count", 25L);
		ICategoryScore score = scoreCategory("OTHER");
		assertDeductionPresent(score, "SYS-0060400");
		assertDeductionAbsent(score, "SYS-0060500");
		assertDeductionAbsent(score, "SYS-0060600");
	}

	// --- Cipher Suite new rules tests ---

	@Test
	void testCipherSuitesRC4Detected() {
		getCipherList().add(Map.of("name", "TLS_RSA_WITH_RC4_128_SHA", "strength", "WEAK", "protocol", "TLSv1.2"));
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0010700");
	}

	@Test
	void testCipherSuitesDESDetected() {
		getCipherList().add(Map.of("name", "TLS_RSA_WITH_DES_CBC_SHA", "strength", "WEAK", "protocol", "TLSv1.2"));
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0010800");
	}

	@Test
	void testCipherSuitesExportDetected() {
		getCipherList().add(Map.of("name", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "strength", "WEAK", "protocol", "TLSv1.2"));
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0010900");
	}

	@Test
	void testCipherSuitesCBCOnly() {
		// Replace all ciphers with only CBC ciphers
		var ciphers = getCipherList();
		ciphers.clear();
		ciphers.add(Map.of("name", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "strength", "MEDIUM", "protocol", "TLSv1.2"));
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011000");
	}

	@Test
	void testCipherSuitesNoForwardSecrecy() {
		var ciphers = getCipherList();
		ciphers.clear();
		ciphers.add(Map.of("name", "TLS_RSA_WITH_AES_128_GCM_SHA256", "strength", "STRONG", "protocol", "TLSv1.2"));
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011100");
	}

	@Test
	void testCipherSuitesNegotiatedNoPFS() {
		getSessionMap().put("negotiated_cipher_suite", "TLS_RSA_WITH_AES_128_GCM_SHA256");
		getSessionMap().put("negotiated_protocol", "TLSv1.2");
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011200");
	}

	@Test
	void testCipherSuitesWeakDHParams() {
		getSessionMap().put("kex_type", "DHE");
		getSessionMap().put("dh_param_size", 1024L);
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011400");
	}

	@Test
	void testCipherSuitesVeryWeakDHParams() {
		getSessionMap().put("kex_type", "DHE");
		getSessionMap().put("dh_param_size", 512L);
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011500");
	}

	@Test
	void testCipherSuitesHonorsClientCipherPreference() {
		getSessionMap().put("honors_client_cipher_preference", true);
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011600");
		assertFalse(findDeduction(score, "SYS-0011600").isInconclusive());
	}

	@Test
	void testCipherSuitesServerEnforcesCipherPreference() {
		getSessionMap().put("honors_client_cipher_preference", false);
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionAbsent(score, "SYS-0011600");
	}

	@Test
	void testCipherSuitesCipherPreferenceInconclusive() {
		getSessionMap().put("honors_client_cipher_preference", null);
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011600");
		assertTrue(findDeduction(score, "SYS-0011600").isInconclusive());
	}

	@Test
	void testCipherSuitesNegotiatedNoAEAD() {
		getSessionMap().put("negotiated_cipher_suite", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
		getSessionMap().put("negotiated_protocol", "TLSv1.2");
		ICategoryScore score = scoreCategory("CIPHER_SUITES");
		assertDeductionPresent(score, "SYS-0011300");
	}

	// --- Certificate new rules tests ---

	@Test
	void testCertificateWildcard() {
		getCertMap().put("has_wildcard_san", true);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021200");
	}

	@Test
	void testCertificateLongValidity() {
		getCertMap().put("days_until_expiration", 500L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021300");
	}

	@Test
	void testCertificateOldVersion() {
		getCertMap().put("version", 1L);
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021400");
	}

	@Test
	void testCertificateMD5Signature() {
		getCertMap().put("signing_algorithm", "MD5withRSA");
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021500");
	}

	@Test
	void testCertificateMD2Signature() {
		getCertMap().put("signing_algorithm", "MD2withRSA");
		ICategoryScore score = scoreCategory("CERTIFICATE");
		assertDeductionPresent(score, "SYS-0021600");
	}

	// --- Security Headers new rules tests ---

	@Test
	void testSecurityHeadersPermissionsPolicyMissing() {
		headers.remove("Permissions-Policy");
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertDeductionPresent(score, "SYS-0040700");
	}

	@Test
	void testSecurityHeadersReferrerPolicyMissing() {
		headers.remove("Referrer-Policy");
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertDeductionPresent(score, "SYS-0040800");
	}

	@Test
	void testSecurityHeadersCOOPMissing() {
		headers.remove("Cross-Origin-Opener-Policy");
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertDeductionPresent(score, "SYS-0040900");
	}

	@Test
	void testSecurityHeadersHSTSNoPreload() {
		headers.put("Strict-Transport-Security", List.of("max-age=63072000; includeSubDomains"));
		ICategoryScore score = scoreCategory("SECURITY_HEADERS");
		assertDeductionPresent(score, "SYS-0041000");
	}

	@Test
	void testOtherMediumSANExposure() {
		getCertMap().put("san_count", 10L);
		ICategoryScore score = scoreCategory("OTHER");
		assertDeductionPresent(score, "SYS-0060500");
		assertDeductionAbsent(score, "SYS-0060400");
	}

	// --- DNS Security tests ---

	@Test
	void testDNSSecurityPerfectScore() {
		ICategoryScore score = scoreCategory("DNS_SECURITY");
		assertEquals(100, score.getScore());
	}

	@Test
	void testDNSSecurityNoCAARecords() {
		getDnsMap().put("has_caa_records", false);
		ICategoryScore score = scoreCategory("DNS_SECURITY");
		assertDeductionPresent(score, "SYS-0050100");
	}

	@Test
	void testDNSSecurityNoTLSARecords() {
		getDnsMap().put("has_tlsa_records", false);
		ICategoryScore score = scoreCategory("DNS_SECURITY");
		assertDeductionPresent(score, "SYS-0050200");
	}

	@Test
	void testDNSSecurityUnavailableInconclusive() {
		Map<String, Object> dns = new LinkedHashMap<>();
		dns.put("available", false);
		rootProps.put("dns", dns);
		ICategoryScore score = scoreCategory("DNS_SECURITY");
		long inconclusiveCount = 0;
		for (IDeduction d : score.getDeductions()) {
			if (d.isInconclusive()) inconclusiveCount++;
		}
		assertTrue(inconclusiveCount >= 2);
	}

	@Test
	void testDeductionSeverityDerivedFromScore() {
		// SSLv2 has score=1.0 which should map to CRITICAL via severity_mapping
		getSet("protocols").add("SSLv2");
		ICategoryScore score = scoreCategory("PROTOCOLS");
		IDeduction d = findDeduction(score, "SYS-0000100");
		assertEquals("CRITICAL", d.getSeverity());
		assertEquals(1.0, d.getScore(), 0.001);
	}

	@Test
	void testCustomCategoryScoring() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: CRITICAL, min_score: 0.8, floor: 65 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  PCI_COMPLIANCE:
				    display_name: "PCI DSS Compliance"
				    rules:
				      pci_tls_version:
				        description: "PCI requires TLS 1.2 or higher"
				        score: 1.0
				        when: protocols contains "TLSv1.0" or protocols contains "TLSv1.1"
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition pciCat = customPolicy.getCategories().get(0);

		// Test with TLS 1.0 present
		getSet("protocols").add("TLSv1.0");
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(pciCat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		assertEquals("PCI_COMPLIANCE", score.getCategoryKey());
		assertNull(score.getCategory()); // Custom category -- no enum match
		assertEquals(0, score.getScore()); // 100 * (1 - 1.0) = 0
		assertDeductionPresent(score, "pci_tls_version");
	}

	@Test
	void testDisabledRuleSkipped() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: HIGH, min_score: 0.5, floor: 75 }
				  - { severity: MEDIUM, min_score: 0.2, floor: 85 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      disabled_rule:
				        description: "This rule is disabled"
				        score: 0.5
				        enabled: false
				        when: "true"
				      enabled_rule:
				        description: "This rule is enabled"
				        score: 0.3
				        when: "true"
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition cat = customPolicy.getCategories().get(0);

		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(cat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		// Only enabled_rule fires: avg=0.3, score = 100*(1-0.3) = 70
		assertEquals(70, score.getScore());
		assertDeductionAbsent(score, "disabled_rule");
		assertDeductionPresent(score, "enabled_rule");
	}

	@Test
	void testAveragingWithMultipleRules() {
		// Test that scores are averaged, not summed
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: HIGH, min_score: 0.5, floor: 75 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      rule1:
				        description: "Rule 1"
				        score: 0.6
				        when: "true"
				      rule2:
				        description: "Rule 2"
				        score: 0.2
				        when: "true"
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition cat = customPolicy.getCategories().get(0);

		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(cat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		// avg = (0.6 + 0.2) / 2 = 0.4, score = 100*(1-0.4) = 60
		assertEquals(60, score.getScore());
	}

	// --- Diagnostics tests ---

	@Test
	void testRuleEvalFailureCapturedAsDiagnostic() {
		// Use an unknown function that parses OK but throws at evaluation time
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: HIGH, min_score: 0.5, floor: 75 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      good_rule:
				        id: "DV-GOOD"
				        description: "This rule works"
				        score: 0.3
				        when: "true"
				      bad_rule:
				        id: "DV-BAD"
				        description: "This rule will fail"
				        score: 0.5
				        when: unknown_function("test") == true
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition cat = customPolicy.getCategories().get(0);

		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(cat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		// Good rule should still fire
		assertDeductionPresent(score, "DV-GOOD");

		// Bad rule should produce a diagnostic
		IScoringDiagnostic[] diags = score.getDiagnostics();
		assertTrue(diags.length > 0, "Should have at least one diagnostic");
		IScoringDiagnostic diag = diags[0];
		assertEquals("DV-BAD", diag.getRuleId());
		assertEquals("TEST", diag.getCategory());
		assertEquals(IScoringDiagnostic.Level.WARNING, diag.getLevel());
		assertTrue(diag.getMessage().contains("bad_rule"), "Message should contain rule id");
	}

	@Test
	void testNoErrorsReturnEmptyDiagnostics() {
		ICategoryScore score = scoreCategory("PROTOCOLS");
		assertEquals(0, score.getDiagnostics().length);
	}

	@Test
	void testDiagnosticHasCorrectSourceLocation() {
		// Use an unknown function that throws at eval time
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      failing_rule:
				        id: "DV-FAIL"
				        description: "Will fail"
				        score: 0.5
				        when: unknown_function("test") == true
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition cat = customPolicy.getCategories().get(0);
		RuleDefinition rule = cat.rules().get(0);
		assertTrue(rule.sourceLine() > 0, "Source line should be > 0");
		assertTrue(rule.sourceColumn() > 0, "Source column should be > 0");

		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(cat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		IScoringDiagnostic[] diags = score.getDiagnostics();
		assertEquals(1, diags.length);
		assertEquals(rule.sourceLine(), diags[0].getLine());
		assertEquals(rule.sourceColumn(), diags[0].getColumn());
	}

	// --- Merge tests ---

	@Test
	void testMergedSystemAndUserRulesScored() {
		// Create user rules that extend the PROTOCOLS category
		String userYaml = """
				categories:
				  PROTOCOLS:
				    display_name: "Protocols"
				    rules:
				      custom_tls10_check:
				        id: USR-0000001
				        description: "User-defined TLS 1.0 check"
				        score: 0.5
				        when: protocols contains "TLSv1.0"
				""";
		RulePolicy userPolicy = RulePolicyLoader.loadUserRules(
				new java.io.ByteArrayInputStream(userYaml.getBytes()));
		RulePolicy merged = policy.mergeUserRules(userPolicy);

		// Trigger the user rule by adding TLS 1.0
		getSet("protocols").add("TLSv1.0");

		CategoryDefinition protocolsCat = merged.getCategories().stream()
				.filter(c -> c.key().equals("PROTOCOLS"))
				.findFirst().orElseThrow();
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(protocolsCat, ctx, merged);
		ICategoryScore score = scorer.score();

		// Both system rule SYS-0000300 (TLS 1.0) and user rule USR-0000001 should fire
		assertDeductionPresent(score, "SYS-0000300");
		assertDeductionPresent(score, "USR-0000001");
	}

	@Test
	void testUserRuleInNewCategory() {
		String userYaml = """
				categories:
				  CUSTOM_CHECKS:
				    display_name: "Custom Checks"
				    rules:
				      always_fires:
				        id: USR-0100001
				        description: "Always fires"
				        score: 0.2
				        when: "true"
				""";
		RulePolicy userPolicy = RulePolicyLoader.loadUserRules(
				new java.io.ByteArrayInputStream(userYaml.getBytes()));
		RulePolicy merged = policy.mergeUserRules(userPolicy);

		// Verify the new category exists in merged policy
		CategoryDefinition customCat = merged.getCategories().stream()
				.filter(c -> c.key().equals("CUSTOM_CHECKS"))
				.findFirst().orElseThrow();

		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(customCat, ctx, merged);
		ICategoryScore score = scorer.score();

		assertDeductionPresent(score, "USR-0100001");
		assertEquals("CUSTOM_CHECKS", score.getCategoryKey());
	}

	// --- Meta interpolation tests ---

	@Test
	void testDefaultUserRiskRulesInfoCategory() {
		// Exercise the exact DEFAULT_USER_RISK_RULES YAML through the full pipeline
		String userYaml = """
				categories:
				  INFO:
				    display_name: "Informational"
				    rules:
				      cert_key_info:
				        id: USR-0000001
				        description: "Certificate uses ${algorithm} ${key_size}-bit key"
				        score: 0.0
				        when: "true"
				        meta:
				          algorithm: cert.key_algorithm
				          key_size: cert.key_size
				      negotiated_connection:
				        id: USR-0000002
				        description: "Negotiated ${protocol} with ${cipher}"
				        score: 0.0
				        when: "true"
				        meta:
				          protocol: session.negotiated_protocol
				          cipher: session.negotiated_cipher_suite
				""";
		RulePolicy userPolicy = RulePolicyLoader.loadUserRules(
				new java.io.ByteArrayInputStream(userYaml.getBytes()));
		RulePolicy merged = policy.mergeUserRules(userPolicy);

		// Verify INFO category exists in merged policy
		CategoryDefinition infoCat = merged.getCategories().stream()
				.filter(c -> c.key().equals("INFO"))
				.findFirst().orElseThrow(() -> new AssertionError("INFO category not found in merged policy"));
		assertEquals("Informational", infoCat.displayName());
		assertEquals(2, infoCat.rules().size());

		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(infoCat, ctx, merged);
		ICategoryScore score = scorer.score();

		// Both rules should fire (when: "true")
		assertEquals(2, score.getDeductions().length, "Both INFO rules should fire");
		assertEquals(100, score.getScore(), "Score 0.0 rules → category score 100");

		// Check cert_key_info deduction
		IDeduction certDed = findDeduction(score, "USR-0000001");
		assertEquals("Certificate uses RSA 4096-bit key", certDed.getDescription());
		assertEquals(0.0, certDed.getScore(), 0.001);
		assertEquals("INFO", certDed.getSeverity());

		// Check negotiated_connection deduction
		IDeduction connDed = findDeduction(score, "USR-0000002");
		assertEquals("Negotiated TLSv1.3 with TLS_AES_256_GCM_SHA384", connDed.getDescription());
		assertEquals(0.0, connDed.getScore(), 0.001);
		assertEquals("INFO", connDed.getSeverity());
	}

	@Test
	void testMetaInterpolatedInDescription() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: HIGH, min_score: 0.5, floor: 75 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      weak_key:
				        id: USR-0000001
				        description: "Key size is ${key_size} bits"
				        score: 0.7
				        when: cert.key_size < 2048
				        meta:
				          key_size: cert.key_size
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition cat = customPolicy.getCategories().get(0);

		getCertMap().put("key_size", 1024L);
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(cat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		IDeduction d = findDeduction(score, "USR-0000001");
		assertEquals("Key size is 1024 bits", d.getDescription());
	}

	@Test
	void testMetaNullValueBecomesEmptyString() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: HIGH, min_score: 0.5, floor: 75 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: F, min_score: 0, risk_level: CRITICAL }
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      curve_check:
				        id: USR-0000002
				        description: "Curve: ${curve}"
				        score: 0.3
				        when: "true"
				        meta:
				          curve: cert.key_curve
				""";
		RulePolicy customPolicy = RulePolicyLoader.loadFromStream(
				new java.io.ByteArrayInputStream(yaml.getBytes()));
		CategoryDefinition cat = customPolicy.getCategories().get(0);

		// cert.key_curve is null in buildPerfectProps
		RuleContext ctx = RuleContext.fromMaps(rootProps, headers);
		ExternalizedCategoryScorer scorer = new ExternalizedCategoryScorer(cat, ctx, customPolicy);
		ICategoryScore score = scorer.score();

		IDeduction d = findDeduction(score, "USR-0000002");
		assertEquals("Curve: ", d.getDescription());
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
	private Map<String, Object> getSessionMap() {
		return (Map<String, Object>) rootProps.get("session");
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> getCertMap() {
		return (Map<String, Object>) rootProps.get("cert");
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> getRevMap() {
		return (Map<String, Object>) rootProps.get("revocation");
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> getDnsMap() {
		return (Map<String, Object>) rootProps.get("dns");
	}

	@SuppressWarnings("unchecked")
	private Set<String> getSet(String key) {
		return (Set<String>) rootProps.get(key);
	}

	@SuppressWarnings("unchecked")
	private List<Map<String, Object>> getCipherList() {
		return (List<Map<String, Object>>) rootProps.get("ciphers");
	}

	private void assertDeductionPresent(ICategoryScore score, String ruleId) {
		for (IDeduction d : score.getDeductions()) {
			if (d.getRuleId().equals(ruleId)) return;
		}
		fail("Expected deduction '" + ruleId + "' not found. Present: " +
				java.util.Arrays.stream(score.getDeductions())
						.map(IDeduction::getRuleId)
						.toList());
	}

	private void assertDeductionAbsent(ICategoryScore score, String ruleId) {
		for (IDeduction d : score.getDeductions()) {
			if (d.getRuleId().equals(ruleId)) {
				fail("Deduction '" + ruleId + "' should not be present");
			}
		}
	}

	private IDeduction findDeduction(ICategoryScore score, String ruleId) {
		for (IDeduction d : score.getDeductions()) {
			if (d.getRuleId().equals(ruleId)) return d;
		}
		fail("Deduction not found: " + ruleId);
		return null;
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> buildPerfectProps() {
		Map<String, Object> props = new HashMap<>();

		Map<String, Object> session = new LinkedHashMap<>();
		session.put("negotiated_protocol", "TLSv1.3");
		session.put("negotiated_cipher_suite", "TLS_AES_256_GCM_SHA384");
		session.put("negotiated_cipher_strength", "STRONG");
		session.put("compression_enabled", false);
		session.put("client_auth_required", false);
		session.put("client_auth_wanted", false);
		session.put("headers_available", true);
		session.put("fingerprint", "abc123def456");
		session.put("fallback_scsv_supported", true);
		session.put("tls_metadata_available", true);
		session.put("renegotiation_info_present", true);
		session.put("early_data_accepted", false);
		session.put("alpn_negotiated", "h2");
		session.put("honors_client_cipher_preference", false);
		session.put("negotiated_group", "X25519MLKEM768");
		session.put("negotiated_group_pq", true);
		session.put("pq_kex_supported", true);
		session.put("pq_kex_groups", "X25519MLKEM768");
		session.put("pq_kex_preferred", true);
		session.put("pq_preferred_group", "X25519MLKEM768");
		session.put("pq_kex_probe_failed", false);
		props.put("session", session);

		// Use mutable set for protocols
		Set<String> protocols = new java.util.HashSet<>();
		protocols.add("TLSv1.2");
		protocols.add("TLSv1.3");
		props.put("protocols", protocols);

		List<Map<String, Object>> ciphers = new java.util.ArrayList<>();
		ciphers.add(Map.of("name", "TLS_AES_256_GCM_SHA384", "strength", "STRONG", "protocol", "TLSv1.3"));
		ciphers.add(Map.of("name", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "strength", "STRONG", "protocol", "TLSv1.2"));
		props.put("ciphers", ciphers);

		Map<String, Object> cert = new LinkedHashMap<>();
		cert.put("validity_state", "VALID");
		cert.put("trust_state", "TRUSTED");
		cert.put("self_signed", false);
		cert.put("java_root", false);
		cert.put("key_algorithm", "RSA");
		cert.put("key_size", 4096L);
		cert.put("key_curve", null);
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

		return props;
	}

	private Map<String, List<String>> buildPerfectHeaders() {
		Map<String, List<String>> h = new LinkedHashMap<>();
		h.put("Strict-Transport-Security", List.of("max-age=63072000; includeSubDomains; preload"));
		h.put("X-Content-Type-Options", List.of("nosniff"));
		h.put("X-Frame-Options", List.of("DENY"));
		h.put("Content-Security-Policy", List.of("default-src 'self'"));
		h.put("Permissions-Policy", List.of("geolocation=()"));
		h.put("Referrer-Policy", List.of("strict-origin-when-cross-origin"));
		h.put("Cross-Origin-Opener-Policy", List.of("same-origin"));
		return h;
	}
}
