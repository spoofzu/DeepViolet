package com.mps.deepviolet.api;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementation of {@link IRiskScore}.
 */
public class RiskScore implements IRiskScore {

	private final int totalScore;
	private final LetterGrade letterGrade;
	private final RiskLevel riskLevel;
	private final String hostUrl;
	private final Map<String, ICategoryScore> categoryScoresByKey;
	private final IScoringDiagnostic[] diagnostics;

	/**
	 * Construct from enum-keyed map (backward compatible).
	 * @param totalScore overall score 0-100
	 * @param letterGrade letter grade
	 * @param riskLevel risk level
	 * @param hostUrl scanned host URL
	 * @param categoryScores per-category scores keyed by enum
	 */
	public RiskScore(int totalScore, LetterGrade letterGrade, RiskLevel riskLevel,
				String hostUrl, Map<ScoreCategory, ICategoryScore> categoryScores) {
		this.totalScore = totalScore;
		this.letterGrade = letterGrade;
		this.riskLevel = riskLevel;
		this.hostUrl = hostUrl;
		this.categoryScoresByKey = new LinkedHashMap<>();
		for (Map.Entry<ScoreCategory, ICategoryScore> entry : categoryScores.entrySet()) {
			this.categoryScoresByKey.put(entry.getKey().name(), entry.getValue());
		}
		this.diagnostics = new IScoringDiagnostic[0];
	}

	/**
	 * Construct from string-keyed map (supports custom categories).
	 * @param totalScore overall score 0-100
	 * @param letterGrade letter grade
	 * @param riskLevel risk level
	 * @param hostUrl scanned host URL
	 * @param categoryScoresByKey per-category scores keyed by string
	 */
	public RiskScore(int totalScore, LetterGrade letterGrade, RiskLevel riskLevel,
				String hostUrl, LinkedHashMap<String, ICategoryScore> categoryScoresByKey) {
		this(totalScore, letterGrade, riskLevel, hostUrl, categoryScoresByKey, List.of());
	}

	/**
	 * Construct from string-keyed map with diagnostics.
	 * @param totalScore overall score 0-100
	 * @param letterGrade letter grade
	 * @param riskLevel risk level
	 * @param hostUrl scanned host URL
	 * @param categoryScoresByKey per-category scores keyed by string
	 * @param diagnostics scoring diagnostics
	 */
	public RiskScore(int totalScore, LetterGrade letterGrade, RiskLevel riskLevel,
				String hostUrl, LinkedHashMap<String, ICategoryScore> categoryScoresByKey,
				List<IScoringDiagnostic> diagnostics) {
		this.totalScore = totalScore;
		this.letterGrade = letterGrade;
		this.riskLevel = riskLevel;
		this.hostUrl = hostUrl;
		this.categoryScoresByKey = new LinkedHashMap<>(categoryScoresByKey);
		this.diagnostics = diagnostics.toArray(new IScoringDiagnostic[0]);
	}

	@Override
	public int getTotalScore() {
		return totalScore;
	}

	@Override
	public LetterGrade getLetterGrade() {
		return letterGrade;
	}

	@Override
	public RiskLevel getRiskLevel() {
		return riskLevel;
	}

	@Override
	public ICategoryScore[] getCategoryScores() {
		return categoryScoresByKey.values().toArray(new ICategoryScore[0]);
	}

	@Override
	public ICategoryScore getCategoryScore(ScoreCategory category) {
		return categoryScoresByKey.get(category.name());
	}

	@Override
	public ICategoryScore getCategoryScore(String categoryKey) {
		return categoryScoresByKey.get(categoryKey);
	}

	@Override
	public String getHostUrl() {
		return hostUrl;
	}

	@Override
	public IScoringDiagnostic[] getDiagnostics() {
		return Arrays.copyOf(diagnostics, diagnostics.length);
	}

	/**
	 * Implementation of {@link IScoringDiagnostic}.
	 */
	public static class ScoringDiagnostic implements IScoringDiagnostic {

		private final String ruleId;
		private final String category;
		private final Level level;
		private final String message;
		private final int line;
		private final int column;

		/**
		 * Construct a scoring diagnostic.
		 * @param ruleId rule identifier
		 * @param category category name
		 * @param level diagnostic level
		 * @param message diagnostic message
		 * @param line line number (0 if N/A)
		 * @param column column number (0 if N/A)
		 */
		public ScoringDiagnostic(String ruleId, String category, Level level,
				String message, int line, int column) {
			this.ruleId = ruleId;
			this.category = category;
			this.level = level;
			this.message = message;
			this.line = line;
			this.column = column;
		}

		@Override public String getRuleId() { return ruleId; }
		@Override public String getCategory() { return category; }
		@Override public Level getLevel() { return level; }
		@Override public String getMessage() { return message; }
		@Override public int getLine() { return line; }
		@Override public int getColumn() { return column; }

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			if (line > 0) {
				sb.append(line).append(':').append(column).append(' ');
			}
			sb.append(level.name());
			if (ruleId != null) {
				sb.append(" [").append(ruleId).append(']');
			}
			sb.append(' ').append(message);
			return sb.toString();
		}
	}

	/**
	 * Implementation of {@link ICategoryScore}.
	 */
	public static class CategoryScore implements ICategoryScore {

		private final ScoreCategory category;
		private final String categoryKey;
		private final int score;
		private final RiskLevel riskLevel;
		private final String displayName;
		private final String summary;
		private final IDeduction[] deductions;
		private final IScoringDiagnostic[] diagnostics;

		/**
		 * Construct for a built-in category.
		 * @param category score category enum
		 * @param score category score 0-100
		 * @param riskLevel risk level
		 * @param displayName display name
		 * @param summary summary text
		 * @param deductions score deductions
		 */
		public CategoryScore(ScoreCategory category, int score,
						RiskLevel riskLevel, String displayName, String summary,
						IDeduction[] deductions) {
			this(category, category != null ? category.name() : null,
					score, riskLevel, displayName, summary, deductions, List.of());
		}

		/**
		 * Construct for a custom (user-defined) category.
		 * @param categoryKey category key string
		 * @param score category score 0-100
		 * @param riskLevel risk level
		 * @param displayName display name
		 * @param summary summary text
		 * @param deductions score deductions
		 */
		public CategoryScore(String categoryKey, int score,
						RiskLevel riskLevel, String displayName, String summary,
						IDeduction[] deductions) {
			this(resolveCategory(categoryKey), categoryKey,
					score, riskLevel, displayName, summary, deductions, List.of());
		}

		/**
		 * Construct for a custom category with diagnostics.
		 * @param categoryKey category key string
		 * @param score category score 0-100
		 * @param riskLevel risk level
		 * @param displayName display name
		 * @param summary summary text
		 * @param deductions score deductions
		 * @param diagnostics scoring diagnostics
		 */
		public CategoryScore(String categoryKey, int score,
						RiskLevel riskLevel, String displayName, String summary,
						IDeduction[] deductions, List<IScoringDiagnostic> diagnostics) {
			this(resolveCategory(categoryKey), categoryKey,
					score, riskLevel, displayName, summary, deductions, diagnostics);
		}

		private CategoryScore(ScoreCategory category, String categoryKey, int score,
						RiskLevel riskLevel, String displayName, String summary,
						IDeduction[] deductions, List<IScoringDiagnostic> diagnostics) {
			this.category = category;
			this.categoryKey = categoryKey;
			this.score = score;
			this.riskLevel = riskLevel;
			this.displayName = displayName;
			this.summary = summary;
			this.deductions = deductions;
			this.diagnostics = diagnostics.toArray(new IScoringDiagnostic[0]);
		}

		private static ScoreCategory resolveCategory(String key) {
			try {
				return ScoreCategory.valueOf(key);
			} catch (IllegalArgumentException e) {
				return null; // Custom category -- no enum match
			}
		}

		@Override
		public ScoreCategory getCategory() { return category; }

		@Override
		public String getCategoryKey() { return categoryKey != null ? categoryKey : (category != null ? category.name() : "UNKNOWN"); }

		@Override
		public int getScore() { return score; }

		@Override
		public RiskLevel getRiskLevel() { return riskLevel; }

		@Override
		public String getDisplayName() { return displayName; }

		@Override
		public String getSummary() { return summary; }

		@Override
		public IDeduction[] getDeductions() { return deductions; }

		@Override
		public IScoringDiagnostic[] getDiagnostics() {
			return Arrays.copyOf(diagnostics, diagnostics.length);
		}
	}

	/**
	 * Implementation of {@link IDeduction.IScope}.
	 */
	public static class Scope implements IDeduction.IScope {

		private final String layer;
		private final String[] protocols;
		private final String aspect;

		/**
		 * Construct a scope.
		 * @param layer scope layer (e.g., "transport")
		 * @param protocols applicable protocols
		 * @param aspect scope aspect
		 */
		public Scope(String layer, String[] protocols, String aspect) {
			this.layer = layer;
			this.protocols = protocols != null ? protocols : new String[0];
			this.aspect = aspect;
		}

		@Override public String getLayer() { return layer; }
		@Override public String[] getProtocols() { return protocols; }
		@Override public String getAspect() { return aspect; }
	}

	/**
	 * Implementation of {@link IDeduction}.
	 */
	public static class Deduction implements IDeduction {

		private final String ruleId;
		private final String description;
		private final double score;
		private final String severity;
		private final boolean inconclusive;
		private final IScope scope;

		/**
		 * Construct a deduction.
		 * @param ruleId rule identifier
		 * @param description description text
		 * @param score score value
		 * @param severity severity level
		 */
		public Deduction(String ruleId, String description, double score, String severity) {
			this(ruleId, description, score, severity, false, null);
		}

		/**
		 * Construct a deduction with inconclusive flag.
		 * @param ruleId rule identifier
		 * @param description description text
		 * @param score score value
		 * @param severity severity level
		 * @param inconclusive true if result is inconclusive
		 */
		public Deduction(String ruleId, String description, double score,
				String severity, boolean inconclusive) {
			this(ruleId, description, score, severity, inconclusive, null);
		}

		/**
		 * Construct a deduction with inconclusive flag and scope.
		 * @param ruleId rule identifier
		 * @param description description text
		 * @param score score value
		 * @param severity severity level
		 * @param inconclusive true if result is inconclusive
		 * @param scope deduction scope
		 */
		public Deduction(String ruleId, String description, double score,
				String severity, boolean inconclusive, IScope scope) {
			this.ruleId = ruleId;
			this.description = description;
			this.score = score;
			this.severity = severity;
			this.inconclusive = inconclusive;
			this.scope = scope;
		}

		@Override
		public String getRuleId() { return ruleId; }

		@Override
		public String getDescription() { return description; }

		@Override
		public double getScore() { return score; }

		@Override
		public String getSeverity() { return severity; }

		@Override
		public boolean isInconclusive() { return inconclusive; }

		@Override
		public IScope getScope() { return scope; }
	}
}
