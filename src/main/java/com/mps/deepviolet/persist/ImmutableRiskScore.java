package com.mps.deepviolet.persist;

import com.mps.deepviolet.api.IRiskScore;

/**
 * Immutable implementation of {@link IRiskScore} for deserialized scan data.
 *
 * @author Milton Smith
 */
public class ImmutableRiskScore implements IRiskScore {

	private final int totalScore;
	private final LetterGrade letterGrade;
	private final RiskLevel riskLevel;
	private final ICategoryScore[] categories;

	/**
	 * Creates an immutable risk score from deserialized fields.
	 *
	 * @param totalScore  the overall numeric score
	 * @param letterGrade the letter grade
	 * @param riskLevel   the risk level
	 * @param categories  the category scores, or {@code null}
	 */
	public ImmutableRiskScore(int totalScore, LetterGrade letterGrade,
			RiskLevel riskLevel, ICategoryScore[] categories) {
		this.totalScore = totalScore;
		this.letterGrade = letterGrade;
		this.riskLevel = riskLevel;
		this.categories = categories != null ? categories : new ICategoryScore[0];
	}

	@Override public int getTotalScore() { return totalScore; }
	@Override public LetterGrade getLetterGrade() { return letterGrade; }
	@Override public RiskLevel getRiskLevel() { return riskLevel; }
	@Override public ICategoryScore[] getCategoryScores() { return categories; }

	@Override
	public ICategoryScore getCategoryScore(ScoreCategory category) {
		for (ICategoryScore cs : categories) {
			if (cs.getCategory() == category) return cs;
		}
		return null;
	}

	@Override
	public ICategoryScore getCategoryScore(String categoryKey) {
		for (ICategoryScore cs : categories) {
			if (cs.getCategoryKey().equals(categoryKey)) return cs;
		}
		return null;
	}

	@Override public String getHostUrl() { return null; }
	@Override public IScoringDiagnostic[] getDiagnostics() {
		return new IScoringDiagnostic[0];
	}
}
