package com.mps.deepviolet.persist;

import static org.junit.jupiter.api.Assertions.*;

import com.mps.deepviolet.api.IRiskScore;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ImmutableRiskScore} and related immutable data holders.
 */
class ImmutableRiskScoreTest {

	@Test
	void testConstructorAndGetters() {
		ImmutableDeduction ded = new ImmutableDeduction(
				"SYS-001", "Test deduction", 5.0, "HIGH", false);
		ImmutableCategoryScore cat = new ImmutableCategoryScore(
				"PROTOCOLS", "Protocols", 15,
				IRiskScore.RiskLevel.MEDIUM, "Protocol summary",
				new IRiskScore.IDeduction[]{ded});
		ImmutableRiskScore score = new ImmutableRiskScore(
				85, IRiskScore.LetterGrade.B,
				IRiskScore.RiskLevel.MEDIUM,
				new IRiskScore.ICategoryScore[]{cat});

		assertEquals(85, score.getTotalScore());
		assertEquals(IRiskScore.LetterGrade.B, score.getLetterGrade());
		assertEquals(IRiskScore.RiskLevel.MEDIUM, score.getRiskLevel());
		assertEquals(1, score.getCategoryScores().length);
		assertNull(score.getHostUrl());
		assertEquals(0, score.getDiagnostics().length);
	}

	@Test
	void testCategoryScoreLookup() {
		ImmutableCategoryScore cat1 = new ImmutableCategoryScore(
				"PROTOCOLS", "Protocols", 18,
				IRiskScore.RiskLevel.LOW, null, null);
		ImmutableCategoryScore cat2 = new ImmutableCategoryScore(
				"CIPHER_SUITES", "Cipher Suites", 12,
				IRiskScore.RiskLevel.MEDIUM, null, null);
		ImmutableRiskScore score = new ImmutableRiskScore(
				80, IRiskScore.LetterGrade.B,
				IRiskScore.RiskLevel.MEDIUM,
				new IRiskScore.ICategoryScore[]{cat1, cat2});

		assertNotNull(score.getCategoryScore(IRiskScore.ScoreCategory.PROTOCOLS));
		assertEquals(18, score.getCategoryScore("PROTOCOLS").getScore());
		assertNotNull(score.getCategoryScore("CIPHER_SUITES"));
		assertNull(score.getCategoryScore("NONEXISTENT"));
		assertNull(score.getCategoryScore(IRiskScore.ScoreCategory.CERTIFICATE));
	}

	@Test
	void testCategoryScoreInterface() {
		ImmutableCategoryScore cat = new ImmutableCategoryScore(
				"PROTOCOLS", "Protocols", 18,
				IRiskScore.RiskLevel.LOW, "Good",
				new IRiskScore.IDeduction[0]);

		assertEquals(IRiskScore.ScoreCategory.PROTOCOLS, cat.getCategory());
		assertEquals("PROTOCOLS", cat.getCategoryKey());
		assertEquals("Protocols", cat.getDisplayName());
		assertEquals(18, cat.getScore());
		assertEquals(IRiskScore.RiskLevel.LOW, cat.getRiskLevel());
		assertEquals("Good", cat.getSummary());
		assertEquals(0, cat.getDeductions().length);
		assertEquals(0, cat.getDiagnostics().length);
	}

	@Test
	void testCategoryScoreUnknownKey() {
		ImmutableCategoryScore cat = new ImmutableCategoryScore(
				"CUSTOM_CATEGORY", "Custom", 10,
				IRiskScore.RiskLevel.LOW, null, null);
		// Unknown category key falls back to OTHER
		assertEquals(IRiskScore.ScoreCategory.OTHER, cat.getCategory());
	}

	@Test
	void testDeductionInterface() {
		ImmutableDeduction ded = new ImmutableDeduction(
				"SYS-0010100", "TLS 1.0 supported", 5.0, "HIGH", false);

		assertEquals("SYS-0010100", ded.getRuleId());
		assertEquals("TLS 1.0 supported", ded.getDescription());
		assertEquals(5.0, ded.getScore(), 0.001);
		assertEquals("HIGH", ded.getSeverity());
		assertFalse(ded.isInconclusive());
	}

	@Test
	void testDeductionInconclusive() {
		ImmutableDeduction ded = new ImmutableDeduction(
				"SYS-002", "Inconclusive check", 0.0, "INFO", true);
		assertTrue(ded.isInconclusive());
	}

	@Test
	void testCipherSuiteInterface() {
		ImmutableCipherSuite cs = new ImmutableCipherSuite(
				"TLS_AES_256_GCM_SHA384", "STRONG", "TLSv1.3");

		assertEquals("TLS_AES_256_GCM_SHA384", cs.getSuiteName());
		assertEquals("STRONG", cs.getStrengthEvaluation());
		assertEquals("TLSv1.3", cs.getHandshakeProtocol());
	}

	@Test
	void testNullCategories() {
		ImmutableRiskScore score = new ImmutableRiskScore(
				100, IRiskScore.LetterGrade.A_PLUS,
				IRiskScore.RiskLevel.LOW, null);
		assertNotNull(score.getCategoryScores());
		assertEquals(0, score.getCategoryScores().length);
	}

	@Test
	void testNullDeductions() {
		ImmutableCategoryScore cat = new ImmutableCategoryScore(
				"PROTOCOLS", "Protocols", 20,
				IRiskScore.RiskLevel.LOW, null, null);
		assertNotNull(cat.getDeductions());
		assertEquals(0, cat.getDeductions().length);
	}
}
