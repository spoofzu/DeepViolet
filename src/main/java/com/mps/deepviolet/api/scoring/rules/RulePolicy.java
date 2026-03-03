package com.mps.deepviolet.api.scoring.rules;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.IRiskScore.LetterGrade;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;

/**
 * Complete loaded YAML rule policy: metadata, severity mapping, grade mapping,
 * and category definitions with pre-parsed expressions.
 */
public class RulePolicy {

	private final String version;
	private final List<SeverityMapping> severityMappings;
	private final List<GradeMapping> gradeMappings;
	private final List<CategoryDefinition> categories;
	private final String sourceFile;

	public RulePolicy(String version, List<SeverityMapping> severityMappings,
			List<GradeMapping> gradeMappings, List<CategoryDefinition> categories) {
		this(version, severityMappings, gradeMappings, categories, null);
	}

	public RulePolicy(String version, List<SeverityMapping> severityMappings,
			List<GradeMapping> gradeMappings, List<CategoryDefinition> categories,
			String sourceFile) {
		this.version = version;
		this.severityMappings = severityMappings;
		this.gradeMappings = gradeMappings;
		this.categories = categories;
		this.sourceFile = sourceFile;
	}

	public String getVersion() {
		return version;
	}

	public List<SeverityMapping> getSeverityMappings() {
		return severityMappings;
	}

	public List<GradeMapping> getGradeMappings() {
		return gradeMappings;
	}

	public List<CategoryDefinition> getCategories() {
		return categories;
	}

	/**
	 * Source filename or resource name from which this policy was loaded, or null if unknown.
	 */
	public String getSourceFile() {
		return sourceFile;
	}

	/**
	 * Determine the severity string for a given rule score (0.0-1.0).
	 * Severity mappings are ordered from highest minScore to lowest;
	 * the first match is returned.
	 */
	public String severityForScore(double score) {
		for (SeverityMapping sm : severityMappings) {
			if (score >= sm.minScore()) {
				return sm.severity();
			}
		}
		return "LOW";
	}

	/**
	 * Determine the score floor for a given rule score (0.0-1.0).
	 * Returns the floor from the highest applicable severity mapping.
	 */
	public int floorForScore(double score) {
		for (SeverityMapping sm : severityMappings) {
			if (score >= sm.minScore()) {
				return sm.floor();
			}
		}
		return 100;
	}

	/**
	 * Determine the letter grade for a given score.
	 */
	public LetterGrade gradeForScore(int score) {
		for (GradeMapping gm : gradeMappings) {
			if (score >= gm.minScore()) {
				return gm.grade();
			}
		}
		return LetterGrade.F;
	}

	/**
	 * Determine the risk level for a given letter grade.
	 */
	public RiskLevel riskLevelForGrade(LetterGrade grade) {
		for (GradeMapping gm : gradeMappings) {
			if (gm.grade() == grade) {
				return gm.riskLevel();
			}
		}
		return RiskLevel.CRITICAL;
	}

	/**
	 * Merge user-defined rules into this (system) policy, returning a new combined policy.
	 * For each user category: if it matches a system category key, user rules are appended
	 * to that category's rule list; otherwise a new category is created.
	 * Does not modify this policy instance.
	 *
	 * @param userRules policy containing user-defined categories with USR- prefixed rules
	 * @return new merged RulePolicy
	 * @throws IllegalArgumentException if duplicate rule IDs are found within a category
	 */
	public RulePolicy mergeUserRules(RulePolicy userRules) {
		// Build a mutable map of system categories keyed by category key
		Map<String, CategoryDefinition> mergedMap = new LinkedHashMap<>();
		for (CategoryDefinition sysCat : this.categories) {
			mergedMap.put(sysCat.key(), sysCat);
		}

		for (CategoryDefinition userCat : userRules.getCategories()) {
			CategoryDefinition existing = mergedMap.get(userCat.key());
			if (existing != null) {
				// Validate no duplicate rule IDs
				Set<String> existingIds = new HashSet<>();
				for (RuleDefinition r : existing.rules()) {
					existingIds.add(r.effectiveId());
				}
				for (RuleDefinition ur : userCat.rules()) {
					if (existingIds.contains(ur.effectiveId())) {
						throw new IllegalArgumentException(
								"Duplicate rule ID '" + ur.effectiveId() + "' in category '" + userCat.key()
								+ "': conflicts with existing system rule");
					}
				}

				// Append user rules to existing category
				List<RuleDefinition> combined = new ArrayList<>(existing.rules());
				combined.addAll(userCat.rules());
				mergedMap.put(userCat.key(),
						new CategoryDefinition(existing.key(), existing.displayName(), combined));
			} else {
				// New category from user rules
				mergedMap.put(userCat.key(), userCat);
			}
		}

		return new RulePolicy(this.version, this.severityMappings, this.gradeMappings,
				new ArrayList<>(mergedMap.values()), this.sourceFile);
	}

	/**
	 * A severity mapping entry from the YAML policy.
	 * Maps a rule score threshold to a severity label and overall score floor.
	 */
	public record SeverityMapping(String severity, double minScore, int floor) {}

	/**
	 * A grade mapping entry from the YAML policy.
	 */
	public record GradeMapping(LetterGrade grade, int minScore, RiskLevel riskLevel) {}
}
