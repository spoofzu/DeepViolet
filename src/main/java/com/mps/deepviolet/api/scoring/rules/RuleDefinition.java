package com.mps.deepviolet.api.scoring.rules;

import java.util.Map;

/**
 * A single scoring rule parsed from YAML.
 *
 * @param id              Stable rule identifier (e.g., "SYS-0000001" or "USR-0000001"), or null if not specified
 * @param ruleId          YAML key name (e.g., "sslv2_supported")
 * @param description     Human-readable description (may contain {@code ${varName}} placeholders for meta interpolation)
 * @param score           Normalized severity score (0.0-1.0) when the rule fires
 * @param enabled         Whether this rule is active
 * @param inconclusive    If true, always mark deduction as inconclusive
 * @param when            Compiled condition expression
 * @param whenInconclusive Compiled inconclusive-path expression, or null
 * @param meta            Named variables backed by DSL expressions, interpolated into description when the rule fires
 * @param scope           Structured scope metadata (layer, protocols, aspect), or null if not specified
 * @param sourceLine      1-based YAML source line where this rule is defined, -1 if unknown
 * @param sourceColumn    1-based YAML source column where this rule is defined, -1 if unknown
 */
public record RuleDefinition(
		String id,
		String ruleId,
		String description,
		double score,
		boolean enabled,
		boolean inconclusive,
		RuleExpression when,
		RuleExpression whenInconclusive,
		Map<String, RuleExpression> meta,
		RuleScope scope,
		int sourceLine,
		int sourceColumn
) {
	/**
	 * Returns the effective rule identifier for deductions.
	 * Prefers the stable {@code id} (SYS-/USR- format) when present,
	 * falls back to the YAML key name.
	 */
	public String effectiveId() {
		return id != null && !id.isBlank() ? id : ruleId;
	}
}
