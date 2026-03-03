package com.mps.deepviolet.api.scoring.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.mps.deepviolet.api.RiskScore.CategoryScore;
import com.mps.deepviolet.api.RiskScore.Deduction;
import com.mps.deepviolet.api.RiskScore.Scope;
import com.mps.deepviolet.api.RiskScore.ScoringDiagnostic;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.IRiskScore.IScoringDiagnostic;
import com.mps.deepviolet.api.IRiskScore.IScoringDiagnostic.Level;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generic expression-driven scorer that evaluates rules from a {@link CategoryDefinition}
 * against a {@link RuleContext}. Uses an average-based scoring model where each rule
 * has a normalized score (0.0-1.0) and results are averaged to produce the category score.
 */
public class ExternalizedCategoryScorer {

	private static final Logger logger = LoggerFactory.getLogger(ExternalizedCategoryScorer.class);

	private final CategoryDefinition category;
	private final RuleContext context;
	private final RulePolicy rulePolicy;

	public ExternalizedCategoryScorer(CategoryDefinition category, RuleContext context,
			RulePolicy rulePolicy) {
		this.category = category;
		this.context = context;
		this.rulePolicy = rulePolicy;
	}

	/**
	 * Evaluate all rules in this category and produce the category score.
	 * <p>
	 * Algorithm:
	 * <ol>
	 *   <li>Evaluate each enabled rule; collect matched rules with their scores</li>
	 *   <li>If no rules match: score = 100, risk = LOW</li>
	 *   <li>Average matched scores: avg = sum(scores) / count</li>
	 *   <li>Category score = (int)(100 * (1.0 - avg))</li>
	 *   <li>Category risk level = severity of highest-scoring matched rule, mapped to RiskLevel</li>
	 * </ol>
	 */
	public ICategoryScore score() {
		List<Deduction> deductions = new ArrayList<>();
		List<IScoringDiagnostic> diagnostics = new ArrayList<>();
		RuleExpressionEvaluator evaluator = new RuleExpressionEvaluator(context);

		for (RuleDefinition rule : category.rules()) {
			if (!rule.enabled()) continue;
			if (rule.when() == null) continue;

			try {
				Scope scope = toScope(rule.scope());

				// Check inconclusive path first
				if (rule.whenInconclusive() != null) {
					if (evaluator.evaluateBoolean(rule.whenInconclusive())) {
						String severity = rulePolicy.severityForScore(rule.score());
						String desc = interpolateDescription(rule.description(), rule.meta(), evaluator);
						deductions.add(new Deduction(
								rule.effectiveId(), desc, rule.score(),
								severity, true, scope));
						continue;
					}
				}

				// Evaluate main condition
				boolean conditionMet = evaluator.evaluateBoolean(rule.when());
				if (conditionMet) {
					boolean isInconclusive = rule.inconclusive();
					String severity = rulePolicy.severityForScore(rule.score());
					String desc = interpolateDescription(rule.description(), rule.meta(), evaluator);
					deductions.add(new Deduction(
							rule.effectiveId(), desc, rule.score(),
							severity, isInconclusive, scope));
				}
			} catch (Exception e) {
				logger.warn("Rule '{}' in category '{}' failed: {}",
						rule.ruleId(), category.key(), e.getMessage());
				String exName = e.getClass().getSimpleName();
				String msg = "Rule '" + rule.ruleId() + "' evaluation failed: " + exName;
				if (e.getMessage() != null) {
					msg += ": " + e.getMessage();
				}
				diagnostics.add(new ScoringDiagnostic(
						rule.effectiveId(), category.key(), Level.WARNING,
						msg, rule.sourceLine(), rule.sourceColumn()));
			}
		}

		int categoryScore;
		RiskLevel riskLevel;

		// Separate conclusive and inconclusive deductions for scoring
		List<Deduction> conclusive = new ArrayList<>();
		for (Deduction d : deductions) {
			if (!d.isInconclusive()) {
				conclusive.add(d);
			}
		}

		if (conclusive.isEmpty()) {
			categoryScore = 100;
			riskLevel = RiskLevel.LOW;
		} else {
			double sum = 0.0;
			double maxRuleScore = 0.0;
			for (Deduction d : conclusive) {
				sum += d.getScore();
				if (d.getScore() > maxRuleScore) {
					maxRuleScore = d.getScore();
				}
			}
			double avg = sum / conclusive.size();
			categoryScore = (int) (100 * (1.0 - avg));

			// Category risk level = severity of highest-scoring matched rule
			String highestSeverity = rulePolicy.severityForScore(maxRuleScore);
			riskLevel = mapSeverityToRiskLevel(highestSeverity);
		}

		String summary = deductions.isEmpty()
				? "No issues found"
				: deductions.size() + " issue(s) found";
		IDeduction[] deductionArray = deductions.toArray(new IDeduction[0]);

		return new CategoryScore(category.key(), categoryScore,
				riskLevel, category.displayName(), summary, deductionArray, diagnostics);
	}

	/**
	 * Replace {@code ${varName}} placeholders in the description with evaluated meta expressions.
	 * Short-circuits if meta is empty or description contains no placeholders.
	 * Unknown variable names are left as-is; null evaluation results become empty strings.
	 */
	private static String interpolateDescription(String description,
			Map<String, RuleExpression> meta, RuleExpressionEvaluator evaluator) {
		if (meta.isEmpty() || description.indexOf("${") < 0) {
			return description;
		}
		StringBuilder sb = new StringBuilder(description.length());
		int i = 0;
		while (i < description.length()) {
			if (i + 1 < description.length() && description.charAt(i) == '$' && description.charAt(i + 1) == '{') {
				int close = description.indexOf('}', i + 2);
				if (close < 0) {
					sb.append(description, i, description.length());
					break;
				}
				String varName = description.substring(i + 2, close);
				RuleExpression expr = meta.get(varName);
				if (expr != null) {
					Object val = evaluator.evaluate(expr);
					sb.append(val != null ? val.toString() : "");
				} else {
					sb.append(description, i, close + 1);
				}
				i = close + 1;
			} else {
				sb.append(description.charAt(i));
				i++;
			}
		}
		return sb.toString();
	}

	private static Scope toScope(RuleScope ruleScope) {
		if (ruleScope == null) return null;
		return new Scope(ruleScope.layer(),
				ruleScope.protocols().toArray(new String[0]),
				ruleScope.aspect());
	}

	private static RiskLevel mapSeverityToRiskLevel(String severity) {
		return switch (severity) {
			case "CRITICAL" -> RiskLevel.CRITICAL;
			case "HIGH" -> RiskLevel.HIGH;
			case "MEDIUM" -> RiskLevel.MEDIUM;
			case "LOW", "INFO" -> RiskLevel.LOW;
			default -> RiskLevel.LOW;
		};
	}
}
