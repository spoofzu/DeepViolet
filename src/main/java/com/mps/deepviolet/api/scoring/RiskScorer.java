package com.mps.deepviolet.api.scoring;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.RiskScore;
import com.mps.deepviolet.api.RiskScore.ScoringDiagnostic;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.IRiskScore.IScoringDiagnostic;
import com.mps.deepviolet.api.IRiskScore.IScoringDiagnostic.Level;
import com.mps.deepviolet.api.IRiskScore.LetterGrade;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;
import com.mps.deepviolet.api.scoring.rules.CategoryDefinition;
import com.mps.deepviolet.api.scoring.rules.ExternalizedCategoryScorer;
import com.mps.deepviolet.api.scoring.rules.RuleContext;
import com.mps.deepviolet.api.scoring.rules.RulePolicy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Orchestrator that runs all category scorers and produces the final risk score.
 * Uses an average-based model:
 * <ol>
 *   <li>Collect all matched rule scores across all categories</li>
 *   <li>Compute global average of conclusive deduction scores</li>
 *   <li>numeric_score = (int)(100 * (1.0 - globalAvg))</li>
 *   <li>Map to letter grade and risk level</li>
 * </ol>
 */
public class RiskScorer {

	private static final Logger logger = LoggerFactory.getLogger(RiskScorer.class);

	private final IEngine engine;
	private final RulePolicy rulePolicy;

	public RiskScorer(IEngine engine, RulePolicy rulePolicy) {
		this.engine = engine;
		this.rulePolicy = rulePolicy;
	}

	/**
	 * Compute the overall risk score by running all category scorers.
	 * @return Complete risk score
	 * @throws DeepVioletException on problems accessing data
	 */
	public IRiskScore computeScore() throws DeepVioletException {
		RuleContext context = RuleContext.from(engine);
		String hostUrl = engine.getSession().getURL().toString();
		return computeScore(context, hostUrl, rulePolicy);
	}

	/**
	 * Score using a pre-built RuleContext (for offline re-scoring).
	 * No engine instance is required.
	 *
	 * @param context pre-built or deserialized RuleContext
	 * @param hostUrl the host URL for the score result
	 * @param rulePolicy the rule policy to evaluate
	 * @return Complete risk score
	 */
	public static IRiskScore computeScore(RuleContext context, String hostUrl,
			RulePolicy rulePolicy) {
		LinkedHashMap<String, ICategoryScore> scores = new LinkedHashMap<>();
		List<IScoringDiagnostic> allDiagnostics = new ArrayList<>();

		// Convert context warnings to diagnostics
		for (String warning : context.getWarnings()) {
			allDiagnostics.add(new ScoringDiagnostic(
					null, null, Level.WARNING, warning, -1, -1));
		}

		// Run category scorers and collect all matched deductions
		double globalScoreSum = 0.0;
		int globalMatchCount = 0;

		for (CategoryDefinition catDef : rulePolicy.getCategories()) {
			try {
				ExternalizedCategoryScorer scorer =
						new ExternalizedCategoryScorer(catDef, context, rulePolicy);
				ICategoryScore catScore = scorer.score();
				scores.put(catDef.key(), catScore);

				// Collect category-level diagnostics
				for (IScoringDiagnostic d : catScore.getDiagnostics()) {
					allDiagnostics.add(d);
				}

				// Accumulate global stats from conclusive deductions only
				for (IDeduction d : catScore.getDeductions()) {
					if (!d.isInconclusive()) {
						globalScoreSum += d.getScore();
						globalMatchCount++;
					}
				}
			} catch (Exception e) {
				logger.warn("Scorer for '{}' failed: {}", catDef.key(), e.getMessage());
				scores.put(catDef.key(), zeroScore(catDef));
				allDiagnostics.add(new ScoringDiagnostic(
						null, catDef.key(), Level.ERROR,
						"Category '" + catDef.key() + "' scoring failed: " + e.getMessage(),
						-1, -1));
			}
		}

		int totalScore;
		if (globalMatchCount == 0) {
			totalScore = 100;
		} else {
			double globalAvg = globalScoreSum / globalMatchCount;
			totalScore = (int) (100 * (1.0 - globalAvg));
		}

		LetterGrade grade = rulePolicy.gradeForScore(totalScore);
		RiskLevel riskLevel = rulePolicy.riskLevelForGrade(grade);

		return new RiskScore(totalScore, grade, riskLevel, hostUrl, scores, allDiagnostics);
	}

	private static ICategoryScore zeroScore(CategoryDefinition catDef) {
		return new RiskScore.CategoryScore(
			catDef.key(), 0,
			RiskLevel.CRITICAL,
			catDef.displayName(),
			"Scoring failed for this category",
			new IRiskScore.IDeduction[0]
		);
	}
}
