package com.mps.deepviolet.persist;

import com.mps.deepviolet.api.IRiskScore;

/**
 * Immutable implementation of {@link IRiskScore.ICategoryScore} for deserialized scan data.
 *
 * @author Milton Smith
 */
public class ImmutableCategoryScore implements IRiskScore.ICategoryScore {

	private final String categoryKey;
	private final String displayName;
	private final int score;
	private final IRiskScore.RiskLevel riskLevel;
	private final String summary;
	private final IRiskScore.IDeduction[] deductions;

	public ImmutableCategoryScore(String categoryKey, String displayName,
			int score, IRiskScore.RiskLevel riskLevel, String summary,
			IRiskScore.IDeduction[] deductions) {
		this.categoryKey = categoryKey;
		this.displayName = displayName;
		this.score = score;
		this.riskLevel = riskLevel;
		this.summary = summary;
		this.deductions = deductions != null ? deductions : new IRiskScore.IDeduction[0];
	}

	@Override
	public IRiskScore.ScoreCategory getCategory() {
		try {
			return IRiskScore.ScoreCategory.valueOf(categoryKey);
		} catch (IllegalArgumentException e) {
			return IRiskScore.ScoreCategory.OTHER;
		}
	}

	@Override public int getScore() { return score; }
	@Override public IRiskScore.RiskLevel getRiskLevel() { return riskLevel; }
	@Override public String getDisplayName() { return displayName; }
	@Override public String getSummary() { return summary; }
	@Override public IRiskScore.IDeduction[] getDeductions() { return deductions; }
	@Override public String getCategoryKey() { return categoryKey; }
	@Override public IRiskScore.IScoringDiagnostic[] getDiagnostics() {
		return new IRiskScore.IScoringDiagnostic[0];
	}
}
