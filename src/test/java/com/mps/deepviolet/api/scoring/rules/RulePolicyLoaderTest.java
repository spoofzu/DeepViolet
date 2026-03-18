package com.mps.deepviolet.api.scoring.rules;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import com.mps.deepviolet.api.IRiskScore.LetterGrade;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;

import org.junit.jupiter.api.Test;

/**
 * Tests for YAML rule policy loading and parsing.
 */
class RulePolicyLoaderTest {

	@Test
	void testLoadBundledYaml() {
		InputStream is = getClass().getClassLoader().getResourceAsStream("risk-scoring-rules.yaml");
		assertNotNull(is, "risk-scoring-rules.yaml should be on classpath");
		RulePolicy policy = RulePolicyLoader.loadFromStream(is);

		assertNotNull(policy);
		assertEquals("3.0", policy.getVersion());
	}

	@Test
	void testSeverityMappingsLoaded() {
		RulePolicy policy = loadBundled();
		assertEquals(5, policy.getSeverityMappings().size());
		assertEquals("CRITICAL", policy.getSeverityMappings().get(0).severity());
		assertEquals(0.8, policy.getSeverityMappings().get(0).minScore(), 0.001);
		assertEquals(65, policy.getSeverityMappings().get(0).floor());
	}

	@Test
	void testSeverityForScore() {
		RulePolicy policy = loadBundled();
		assertEquals("CRITICAL", policy.severityForScore(1.0));
		assertEquals("CRITICAL", policy.severityForScore(0.8));
		assertEquals("HIGH", policy.severityForScore(0.7));
		assertEquals("HIGH", policy.severityForScore(0.5));
		assertEquals("MEDIUM", policy.severityForScore(0.3));
		assertEquals("MEDIUM", policy.severityForScore(0.2));
		assertEquals("LOW", policy.severityForScore(0.1));
		assertEquals("INFO", policy.severityForScore(0.0));
	}

	@Test
	void testFloorForScore() {
		RulePolicy policy = loadBundled();
		assertEquals(65, policy.floorForScore(1.0));
		assertEquals(65, policy.floorForScore(0.8));
		assertEquals(75, policy.floorForScore(0.5));
		assertEquals(85, policy.floorForScore(0.2));
		assertEquals(100, policy.floorForScore(0.1));
	}

	@Test
	void testGradeMappingsLoaded() {
		RulePolicy policy = loadBundled();
		assertEquals(6, policy.getGradeMappings().size());
		assertEquals(LetterGrade.A_PLUS, policy.getGradeMappings().get(0).grade());
		assertEquals(95, policy.getGradeMappings().get(0).minScore());
		assertEquals(RiskLevel.LOW, policy.getGradeMappings().get(0).riskLevel());
	}

	@Test
	void testGradeForScore() {
		RulePolicy policy = loadBundled();
		assertEquals(LetterGrade.A_PLUS, policy.gradeForScore(100));
		assertEquals(LetterGrade.A_PLUS, policy.gradeForScore(95));
		assertEquals(LetterGrade.A, policy.gradeForScore(90));
		assertEquals(LetterGrade.B, policy.gradeForScore(80));
		assertEquals(LetterGrade.C, policy.gradeForScore(70));
		assertEquals(LetterGrade.D, policy.gradeForScore(60));
		assertEquals(LetterGrade.F, policy.gradeForScore(0));
	}

	@Test
	void testRiskLevelForGrade() {
		RulePolicy policy = loadBundled();
		assertEquals(RiskLevel.LOW, policy.riskLevelForGrade(LetterGrade.A_PLUS));
		assertEquals(RiskLevel.LOW, policy.riskLevelForGrade(LetterGrade.A));
		assertEquals(RiskLevel.MEDIUM, policy.riskLevelForGrade(LetterGrade.B));
		assertEquals(RiskLevel.HIGH, policy.riskLevelForGrade(LetterGrade.C));
		assertEquals(RiskLevel.CRITICAL, policy.riskLevelForGrade(LetterGrade.D));
		assertEquals(RiskLevel.CRITICAL, policy.riskLevelForGrade(LetterGrade.F));
	}

	@Test
	void testAllCategoriesLoaded() {
		RulePolicy policy = loadBundled();
		assertEquals(7, policy.getCategories().size());

		var catKeys = policy.getCategories().stream().map(CategoryDefinition::key).toList();
		assertTrue(catKeys.contains("PROTOCOLS"));
		assertTrue(catKeys.contains("CIPHER_SUITES"));
		assertTrue(catKeys.contains("CERTIFICATE"));
		assertTrue(catKeys.contains("REVOCATION"));
		assertTrue(catKeys.contains("SECURITY_HEADERS"));
		assertTrue(catKeys.contains("DNS_SECURITY"));
		assertTrue(catKeys.contains("OTHER"));
	}

	@Test
	void testProtocolsCategoryDetails() {
		RulePolicy policy = loadBundled();
		CategoryDefinition protocols = findCategory(policy, "PROTOCOLS");
		assertEquals("Protocols & Connections", protocols.displayName());
		assertEquals(15, protocols.rules().size());

		RuleDefinition sslv2 = findRule(protocols, "sslv2_supported");
		assertEquals("SYS-0000100", sslv2.id());
		assertEquals("SYS-0000100", sslv2.effectiveId());
		assertEquals(1.0, sslv2.score(), 0.001);
		assertTrue(sslv2.enabled());
		assertNotNull(sslv2.when());
	}

	@Test
	void testAllBundledRulesHaveStableIds() {
		RulePolicy policy = loadBundled();
		for (CategoryDefinition cat : policy.getCategories()) {
			for (RuleDefinition rule : cat.rules()) {
				assertNotNull(rule.id(), "Rule " + rule.ruleId() + " should have a stable SYS- id");
				assertTrue(rule.id().startsWith("SYS-"),
						"Rule " + rule.ruleId() + " id should start with SYS- but was: " + rule.id());
				assertEquals(rule.id(), rule.effectiveId(),
						"effectiveId() should return DV-R id when present");
			}
		}
	}

	@Test
	void testCipherSuitesCategoryDetails() {
		RulePolicy policy = loadBundled();
		CategoryDefinition ciphers = findCategory(policy, "CIPHER_SUITES");
		assertEquals(16, ciphers.rules().size());
	}

	@Test
	void testCertificateCategoryDetails() {
		RulePolicy policy = loadBundled();
		CategoryDefinition cert = findCategory(policy, "CERTIFICATE");
		assertEquals(17, cert.rules().size());
	}

	@Test
	void testRevocationCategoryDetails() {
		RulePolicy policy = loadBundled();
		CategoryDefinition rev = findCategory(policy, "REVOCATION");
		assertEquals(7, rev.rules().size());

		// Check inconclusive rule
		RuleDefinition errors = findRule(rev, "revocation_check_errors");
		assertTrue(errors.inconclusive());
	}

	@Test
	void testSecurityHeadersCategoryDetails() {
		RulePolicy policy = loadBundled();
		CategoryDefinition headers = findCategory(policy, "SECURITY_HEADERS");
		assertEquals(10, headers.rules().size());

		// Check when_inconclusive on no_hsts
		RuleDefinition noHsts = findRule(headers, "no_hsts");
		assertNotNull(noHsts.when());
		assertNotNull(noHsts.whenInconclusive());
	}

	@Test
	void testOtherCategoryDetails() {
		RulePolicy policy = loadBundled();
		CategoryDefinition other = findCategory(policy, "OTHER");
		assertEquals(7, other.rules().size());

		RuleDefinition fingerprint = findRule(other, "fingerprint_unavailable");
		assertTrue(fingerprint.inconclusive());
	}

	@Test
	void testAllRuleScoresInRange() {
		RulePolicy policy = loadBundled();
		for (CategoryDefinition cat : policy.getCategories()) {
			for (RuleDefinition rule : cat.rules()) {
				assertTrue(rule.score() >= 0.0 && rule.score() <= 1.0,
						"Rule " + rule.ruleId() + " score should be 0.0-1.0 but was: " + rule.score());
			}
		}
	}

	@Test
	void testAllExpressionsPreParsed() {
		RulePolicy policy = loadBundled();
		for (CategoryDefinition cat : policy.getCategories()) {
			for (RuleDefinition rule : cat.rules()) {
				assertNotNull(rule.when(), "Rule " + rule.ruleId() + " should have a 'when' expression");
			}
		}
	}

	@Test
	void testCustomCategoryParsing() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping:
				  - { severity: CRITICAL, min_score: 0.8, floor: 65 }
				  - { severity: LOW, min_score: 0.0, floor: 100 }
				grade_mapping:
				  - { grade: A_PLUS, min_score: 95, risk_level: LOW }
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

		RulePolicy policy = RulePolicyLoader.loadFromStream(
				new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		assertEquals(1, policy.getCategories().size());
		CategoryDefinition pci = policy.getCategories().get(0);
		assertEquals("PCI_COMPLIANCE", pci.key());
		assertEquals(1, pci.rules().size());
		assertEquals(1.0, pci.rules().get(0).score(), 0.001);
		assertNotNull(pci.rules().get(0).when());
	}

	@Test
	void testRuleWithoutIdFallsBackToRuleId() {
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
				      my_custom_rule:
				        description: "No id field"
				        score: 0.5
				        when: "true"
				""";

		RulePolicy policy = RulePolicyLoader.loadFromStream(
				new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		RuleDefinition rule = policy.getCategories().get(0).rules().get(0);
		assertNull(rule.id());
		assertEquals("my_custom_rule", rule.ruleId());
		assertEquals("my_custom_rule", rule.effectiveId());
	}

	@Test
	void testDisabledRule() {
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
				      disabled_rule:
				        description: "This rule is disabled"
				        score: 0.5
				        enabled: false
				        when: "true"
				""";

		RulePolicy policy = RulePolicyLoader.loadFromStream(
				new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		RuleDefinition rule = policy.getCategories().get(0).rules().get(0);
		assertFalse(rule.enabled());
	}

	@Test
	void testLoadedRulesHaveSourceLocations() {
		RulePolicy policy = loadBundled();
		for (CategoryDefinition cat : policy.getCategories()) {
			for (RuleDefinition rule : cat.rules()) {
				assertTrue(rule.sourceLine() > 0,
						"Rule " + rule.ruleId() + " should have sourceLine > 0 but was: " + rule.sourceLine());
				assertTrue(rule.sourceColumn() > 0,
						"Rule " + rule.ruleId() + " should have sourceColumn > 0 but was: " + rule.sourceColumn());
			}
		}
	}

	@Test
	void testSourceFileStoredOnPolicy() {
		RulePolicy policy = RulePolicyLoader.loadFromStream(
				new ByteArrayInputStream("metadata:\n  version: '1.0'\nseverity_mapping: []\ngrade_mapping: []\ncategories: {}".getBytes(StandardCharsets.UTF_8)),
				"my-rules.yaml");
		assertEquals("my-rules.yaml", policy.getSourceFile());
	}

	@Test
	void testSourceFileNullByDefault() {
		RulePolicy policy = RulePolicyLoader.loadFromStream(
				new ByteArrayInputStream("metadata:\n  version: '1.0'\nseverity_mapping: []\ngrade_mapping: []\ncategories: {}".getBytes(StandardCharsets.UTF_8)));
		assertNull(policy.getSourceFile());
	}

	@Test
	void testMalformedExpressionIncludesLineColumn() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping: []
				grade_mapping: []
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      bad_rule:
				        description: "Bad expression"
				        score: 0.5
				        when: "== == =="
				""";

		IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
				RulePolicyLoader.loadFromStream(
						new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
		// Error message should include a line:column prefix
		assertTrue(ex.getMessage().matches("\\d+:\\d+ .*"),
				"Error message should start with line:column but was: " + ex.getMessage());
	}

	@Test
	void testMalformedExpressionThrows() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping: []
				grade_mapping: []
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      bad_rule:
				        description: "Bad expression"
				        score: 0.5
				        when: "== == =="
				""";

		assertThrows(IllegalArgumentException.class, () ->
				RulePolicyLoader.loadFromStream(
						new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
	}

	@Test
	void testLoadUserRulesValid() {
		String yaml = """
				categories:
				  PROTOCOLS:
				    display_name: "Protocols"
				    rules:
				      custom_check:
				        id: USR-0000001
				        description: "Custom protocol check"
				        score: 0.4
				        when: protocols contains "TLSv1.0"
				""";
		RulePolicy userPolicy = RulePolicyLoader.loadUserRules(
				new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		assertEquals("user", userPolicy.getVersion());
		assertTrue(userPolicy.getSeverityMappings().isEmpty());
		assertTrue(userPolicy.getGradeMappings().isEmpty());
		assertEquals(1, userPolicy.getCategories().size());

		CategoryDefinition cat = userPolicy.getCategories().get(0);
		assertEquals("PROTOCOLS", cat.key());
		assertEquals(1, cat.rules().size());
		assertEquals("USR-0000001", cat.rules().get(0).id());
	}

	@Test
	void testLoadUserRulesSysPrefixRejected() {
		String yaml = """
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      bad_rule:
				        id: SYS-0000001
				        description: "Should be rejected"
				        score: 0.5
				        when: "true"
				""";
		assertThrows(IllegalArgumentException.class, () ->
				RulePolicyLoader.loadUserRules(
						new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
	}

	@Test
	void testLoadUserRulesNoSeverityMapping() {
		String yaml = """
				categories:
				  CUSTOM:
				    display_name: "Custom"
				    rules:
				      my_rule:
				        id: USR-0000010
				        description: "A user rule"
				        score: 0.3
				        when: "true"
				""";
		RulePolicy userPolicy = RulePolicyLoader.loadUserRules(
				new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		assertTrue(userPolicy.getSeverityMappings().isEmpty());
		assertTrue(userPolicy.getGradeMappings().isEmpty());
		assertEquals(1, userPolicy.getCategories().size());
	}

	@Test
	void testLoadUserRulesMissingIdThrows() {
		String yaml = """
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      no_id_rule:
				        description: "No id field"
				        score: 0.5
				        when: "true"
				""";
		assertThrows(IllegalArgumentException.class, () ->
				RulePolicyLoader.loadUserRules(
						new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
	}

	@Test
	void testMetaParsed() {
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
				      meta_rule:
				        id: USR-0000001
				        description: "Key size is ${key_size} bits"
				        score: 0.7
				        when: cert.key_size < 2048
				        meta:
				          key_size: cert.key_size
				""";

		RulePolicy policy = RulePolicyLoader.loadFromStream(
				new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

		RuleDefinition rule = policy.getCategories().get(0).rules().get(0);
		assertNotNull(rule.meta());
		assertEquals(1, rule.meta().size());
		assertTrue(rule.meta().containsKey("key_size"));
	}

	@Test
	void testMetaEmptyByDefault() {
		RulePolicy policy = loadBundled();
		for (CategoryDefinition cat : policy.getCategories()) {
			for (RuleDefinition rule : cat.rules()) {
				assertNotNull(rule.meta(),
						"Rule " + rule.ruleId() + " should have non-null meta");
				// pq_kex_available and pq_kex_negotiated have meta for group interpolation
				if ("pq_kex_available".equals(rule.ruleId())
						|| "pq_kex_negotiated".equals(rule.ruleId())) {
					assertFalse(rule.meta().isEmpty(),
							"Rule " + rule.ruleId() + " should have non-empty meta");
					continue;
				}
				assertTrue(rule.meta().isEmpty(),
						"Rule " + rule.ruleId() + " should have empty meta but had: " + rule.meta());
			}
		}
	}

	@Test
	void testMetaMalformedExpressionThrows() {
		String yaml = """
				metadata:
				  version: "3.0"
				severity_mapping: []
				grade_mapping: []
				categories:
				  TEST:
				    display_name: "Test"
				    rules:
				      bad_meta_rule:
				        description: "Bad meta"
				        score: 0.5
				        when: "true"
				        meta:
				          bad_var: "== == =="
				""";

		assertThrows(IllegalArgumentException.class, () ->
				RulePolicyLoader.loadFromStream(
						new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8))));
	}

	private RulePolicy loadBundled() {
		InputStream is = getClass().getClassLoader().getResourceAsStream("risk-scoring-rules.yaml");
		return RulePolicyLoader.loadFromStream(is);
	}

	private CategoryDefinition findCategory(RulePolicy policy, String key) {
		return policy.getCategories().stream()
				.filter(c -> c.key().equals(key))
				.findFirst()
				.orElseThrow(() -> new AssertionError("Category not found: " + key));
	}

	private RuleDefinition findRule(CategoryDefinition cat, String ruleId) {
		return cat.rules().stream()
				.filter(r -> r.ruleId().equals(ruleId))
				.findFirst()
				.orElseThrow(() -> new AssertionError("Rule not found: " + ruleId));
	}
}
