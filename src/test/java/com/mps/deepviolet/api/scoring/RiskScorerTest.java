package com.mps.deepviolet.api.scoring;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IDnsStatus;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IRevocationStatus;
import com.mps.deepviolet.api.IRevocationStatus.RevocationResult;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.IRiskScore.IScoringDiagnostic;
import com.mps.deepviolet.api.IRiskScore.LetterGrade;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;
import com.mps.deepviolet.api.IX509Certificate.TrustState;
import com.mps.deepviolet.api.IX509Certificate.ValidState;
import com.mps.deepviolet.api.tls.TlsMetadata;
import com.mps.deepviolet.api.scoring.rules.RulePolicy;
import com.mps.deepviolet.api.scoring.rules.RulePolicyLoader;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RiskScorerTest {

	private IEngine engine;
	private ISession session;
	private IX509Certificate cert;
	private IRevocationStatus revStatus;
	private RulePolicy rulePolicy;

	@BeforeEach
	void setUp() throws Exception {
		engine = mock(IEngine.class);
		session = mock(ISession.class);
		cert = mock(IX509Certificate.class);
		revStatus = mock(IRevocationStatus.class);

		when(engine.getSession()).thenReturn(session);
		when(session.getURL()).thenReturn(new URL("https://example.com"));
		when(engine.getCertificate()).thenReturn(cert);

		InputStream is = getClass().getClassLoader().getResourceAsStream("risk-scoring-rules.yaml");
		rulePolicy = RulePolicyLoader.loadFromStream(is);
	}

	@Test
	public void testPerfectScoreGivesAPlus() throws Exception {
		setupPerfectMocks();

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		assertEquals(100, result.getTotalScore());
		assertEquals(LetterGrade.A_PLUS, result.getLetterGrade());
		assertEquals(RiskLevel.LOW, result.getRiskLevel());
		assertEquals("https://example.com", result.getHostUrl());
		assertEquals(7, result.getCategoryScores().length);
	}

	@Test
	public void testAllCategoriesPresent() throws Exception {
		setupPerfectMocks();

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		String[] expectedKeys = {"PROTOCOLS", "CIPHER_SUITES", "CERTIFICATE",
				"REVOCATION", "SECURITY_HEADERS", "DNS_SECURITY", "OTHER"};
		for (String key : expectedKeys) {
			ICategoryScore catScore = result.getCategoryScore(key);
			assertNotNull(catScore, "Category " + key + " should be present");
			assertEquals(key, catScore.getCategoryKey());
		}
	}

	@Test
	public void testGradeMappingWithDeductions() throws Exception {
		setupPerfectMocks();
		// Add SSLv2 to trigger protocol deduction (score=1.0, CRITICAL)
		ICipherSuite sslv2 = mockCipher("SSLv2", "STRONG", "SSL_CIPHER");
		ICipherSuite tls13 = mockCipher("TLSv1.3", "STRONG", "TLS_AES_256_GCM_SHA384");
		when(engine.getCipherSuites()).thenReturn(new ICipherSuite[]{ sslv2, tls13 });

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		assertTrue(result.getTotalScore() < 100, "Score should reflect deductions");
		assertNotEquals(LetterGrade.A_PLUS, result.getLetterGrade());
	}

	@Test
	public void testAverageAndFloorAlgorithm() throws Exception {
		setupPerfectMocks();
		// Make some headers missing to get a non-perfect score
		when(session.getHttpResponseHeaders()).thenReturn(new HashMap<>());

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		// With missing headers, there should be deductions
		assertTrue(result.getTotalScore() < 100);
		assertTrue(result.getTotalScore() >= 0);
		assertNotNull(result.getLetterGrade());
	}

	@Test
	public void testCriticalRuleReducesScore() throws Exception {
		setupPerfectMocks();
		// Make cert expired (score=1.0, CRITICAL severity)
		when(cert.getValidityState()).thenReturn(ValidState.EXPIRED);

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		// Score should reflect the deduction without artificial flooring
		assertTrue(result.getTotalScore() < 100,
				"Score " + result.getTotalScore() + " should be reduced by critical deduction");
	}

	@Test
	public void testContextWarningsSurfacedInDiagnostics() throws Exception {
		setupPerfectMocks();
		// Make TLS fingerprint throw to trigger a context warning
		when(engine.getTlsFingerprint()).thenThrow(new DeepVioletException("fingerprint timeout"));

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		IScoringDiagnostic[] diags = result.getDiagnostics();
		boolean foundWarning = false;
		for (IScoringDiagnostic d : diags) {
			if (d.getMessage().contains("fingerprint") && d.getLevel() == IScoringDiagnostic.Level.WARNING) {
				foundWarning = true;
				assertNull(d.getRuleId(), "Context warning should have null ruleId");
				assertNull(d.getCategory(), "Context warning should have null category");
				assertEquals(-1, d.getLine());
				break;
			}
		}
		assertTrue(foundWarning, "Should find fingerprint warning in diagnostics");
	}

	@Test
	public void testPerfectScoreHasNoDiagnostics() throws Exception {
		setupPerfectMocks();

		RiskScorer scorer = new RiskScorer(engine, rulePolicy);
		IRiskScore result = scorer.computeScore();

		assertEquals(0, result.getDiagnostics().length);
	}

	@Test
	public void testGetRiskScoreWithUserRulesStream() throws Exception {
		setupPerfectMocks();

		// Create user rules that add a custom check
		String userYaml = """
				categories:
				  CUSTOM_USER_CHECKS:
				    display_name: "Custom User Checks"
				    rules:
				      always_fires:
				        id: USR-0000001
				        description: "Always fires user rule"
				        score: 0.2
				        when: "true"
				""";

		// Load system policy and merge user rules
		RulePolicy systemPolicy = rulePolicy;
		RulePolicy userPolicy = RulePolicyLoader.loadUserRules(
				new ByteArrayInputStream(userYaml.getBytes(StandardCharsets.UTF_8)));
		RulePolicy mergedPolicy = systemPolicy.mergeUserRules(userPolicy);

		RiskScorer scorer = new RiskScorer(engine, mergedPolicy);
		IRiskScore result = scorer.computeScore();

		// Should have the 7 system categories + 1 user category = 8
		assertEquals(8, result.getCategoryScores().length);

		// User category should be present and have the user rule deduction
		ICategoryScore userCatScore = result.getCategoryScore("CUSTOM_USER_CHECKS");
		assertNotNull(userCatScore, "User category CUSTOM_USER_CHECKS should be present");
		boolean foundUserRule = false;
		for (IDeduction d : userCatScore.getDeductions()) {
			if ("USR-0000001".equals(d.getRuleId())) {
				foundUserRule = true;
				break;
			}
		}
		assertTrue(foundUserRule, "User rule USR-0000001 should fire");
	}

	private void setupPerfectMocks() throws DeepVioletException {
		// Protocols: TLS 1.3 + TLS 1.2 with ECDHE/GCM
		ICipherSuite tls13 = mockCipher("TLSv1.3", "STRONG", "TLS_AES_256_GCM_SHA384");
		ICipherSuite tls12 = mockCipher("TLSv1.2", "STRONG", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
		when(engine.getCipherSuites()).thenReturn(new ICipherSuite[]{ tls13, tls12 });
		when(session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_PROTOCOL)).thenReturn("TLSv1.3");
		when(session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_CIPHER_SUITE)).thenReturn(null);

		// Certificate: valid, trusted, good key
		when(cert.getValidityState()).thenReturn(ValidState.VALID);
		when(cert.getTrustState()).thenReturn(TrustState.TRUSTED);
		when(cert.isSelfSignedCertificate()).thenReturn(false);
		when(cert.isJavaRootCertificate()).thenReturn(false);
		when(cert.getPublicKeyAlgorithm()).thenReturn("RSA");
		when(cert.getPublicKeySize()).thenReturn(4096);
		when(cert.getSigningAlgorithm()).thenReturn("SHA256withRSA");
		when(cert.getDaysUntilExpiration()).thenReturn(365L);
		when(cert.getCertificateChain()).thenReturn(new IX509Certificate[]{ cert, mock(IX509Certificate.class) });
		when(cert.getSubjectAlternativeNames()).thenReturn(Collections.singletonList("example.com"));

		// Revocation: all good
		when(cert.getRevocationStatus()).thenReturn(revStatus);
		when(revStatus.getOcspStatus()).thenReturn(RevocationResult.GOOD);
		when(revStatus.getCrlStatus()).thenReturn(RevocationResult.GOOD);
		when(revStatus.isOcspStaplingPresent()).thenReturn(true);
		when(revStatus.isMustStaplePresent()).thenReturn(true);
		when(revStatus.getSctCount()).thenReturn(3);

		// Certificate version
		when(cert.getCertificateVersion()).thenReturn(3);
		when(cert.getPublicKeyCurve()).thenReturn(null);

		// Security headers: all present
		Map<String, List<String>> headers = new HashMap<>();
		headers.put("Strict-Transport-Security", Arrays.asList("max-age=63072000; includeSubDomains; preload"));
		headers.put("X-Content-Type-Options", Arrays.asList("nosniff"));
		headers.put("X-Frame-Options", Arrays.asList("DENY"));
		headers.put("Content-Security-Policy", Arrays.asList("default-src 'self'"));
		headers.put("Permissions-Policy", Arrays.asList("geolocation=()"));
		headers.put("Referrer-Policy", Arrays.asList("strict-origin-when-cross-origin"));
		headers.put("Cross-Origin-Opener-Policy", Arrays.asList("same-origin"));
		when(session.getHttpResponseHeaders()).thenReturn(headers);

		// TLS metadata (null = unavailable, rules become inconclusive)
		when(engine.getTlsMetadata()).thenReturn(null);
		when(engine.getFallbackScsvSupported()).thenReturn(true);

		// DNS security: mock with CAA and TLSA present
		IDnsStatus dnsStatus = mock(IDnsStatus.class);
		when(dnsStatus.isAvailable()).thenReturn(true);
		when(dnsStatus.hasCaaRecords()).thenReturn(true);
		when(dnsStatus.hasTlsaRecords()).thenReturn(true);
		when(engine.getDnsStatus()).thenReturn(dnsStatus);

		// Other: no compression, no client auth, fingerprint available
		when(session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.DEFLATE_COMPRESSION)).thenReturn("false");
		when(session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.CLIENT_AUTH_REQ)).thenReturn("false");
		when(engine.getTlsFingerprint()).thenReturn("abc123def456");
	}

	private ICipherSuite mockCipher(String protocol, String strength, String name) {
		ICipherSuite cipher = mock(ICipherSuite.class);
		when(cipher.getHandshakeProtocol()).thenReturn(protocol);
		when(cipher.getStrengthEvaluation()).thenReturn(strength);
		when(cipher.getSuiteName()).thenReturn(name);
		return cipher;
	}
}
