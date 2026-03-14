package com.mps.deepviolet.persist;

import com.mps.deepviolet.api.IRiskScore;

/**
 * Immutable implementation of {@link IRiskScore.IDeduction} for deserialized scan data.
 *
 * @author Milton Smith
 */
public class ImmutableDeduction implements IRiskScore.IDeduction {

	private final String ruleId;
	private final String description;
	private final double score;
	private final String severity;
	private final boolean inconclusive;

	public ImmutableDeduction(String ruleId, String description,
			double score, String severity, boolean inconclusive) {
		this.ruleId = ruleId;
		this.description = description;
		this.score = score;
		this.severity = severity;
		this.inconclusive = inconclusive;
	}

	@Override public String getRuleId() { return ruleId; }
	@Override public String getDescription() { return description; }
	@Override public double getScore() { return score; }
	@Override public String getSeverity() { return severity; }
	@Override public boolean isInconclusive() { return inconclusive; }
}
