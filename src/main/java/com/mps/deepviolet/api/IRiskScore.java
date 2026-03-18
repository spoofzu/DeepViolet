package com.mps.deepviolet.api;

/**
 * Public interface for TLS risk score results.
 * Provides a quantitative risk assessment using an average-based scoring model
 * with severity floors, mapped to letter grades and traffic-light risk levels.
 *
 * @author Milton Smith
 */
public interface IRiskScore {

	/** Risk level indicating overall threat severity. */
	enum RiskLevel {
		/** Low risk. */
		LOW,
		/** Medium risk. */
		MEDIUM,
		/** High risk. */
		HIGH,
		/** Critical risk. */
		CRITICAL
	}

	/** Letter grade derived from a numeric risk score. */
	enum LetterGrade {
		/** A+ grade. */
		A_PLUS("A+"),
		/** A grade. */
		A("A"),
		/** B grade. */
		B("B"),
		/** C grade. */
		C("C"),
		/** D grade. */
		D("D"),
		/** F grade. */
		F("F");

		private final String display;
		LetterGrade(String display) { this.display = display; }

		/** Human-readable grade string (e.g. "A+", "B").
		 * @return display string */
		public String toDisplayString() { return display; }
	}

	/** Categories used to group related scoring rules. */
	enum ScoreCategory {
		/** Protocol version scoring. */
		PROTOCOLS,
		/** Cipher suite scoring. */
		CIPHER_SUITES,
		/** Certificate scoring. */
		CERTIFICATE,
		/** Revocation checking scoring. */
		REVOCATION,
		/** HTTP security headers scoring. */
		SECURITY_HEADERS,
		/** DNS security (CAA, DANE) scoring. */
		DNS_SECURITY,
		/** Miscellaneous scoring. */
		OTHER
	}

	/**
	 * Total score across all categories (0-100).
	 * @return Total risk score
	 */
	int getTotalScore();

	/**
	 * Letter grade derived from total score.
	 * @return Letter grade
	 */
	LetterGrade getLetterGrade();

	/**
	 * Overall risk level derived from the letter grade.
	 * @return Risk level
	 */
	RiskLevel getRiskLevel();

	/**
	 * Per-category score breakdowns.
	 * @return Array of category scores
	 */
	ICategoryScore[] getCategoryScores();

	/**
	 * Get a specific category's score by enum.
	 * @param category The category to retrieve
	 * @return Category score, or null if not found
	 */
	ICategoryScore getCategoryScore(ScoreCategory category);

	/**
	 * Get a specific category's score by string key.
	 * Works for both built-in categories (e.g., "PROTOCOLS") and
	 * user-defined custom categories (e.g., "PCI_COMPLIANCE").
	 * @param categoryKey The category key string
	 * @return Category score, or null if not found
	 */
	ICategoryScore getCategoryScore(String categoryKey);

	/**
	 * Host URL that was scored.
	 * @return Host URL string
	 */
	String getHostUrl();

	/**
	 * Diagnostics collected during scoring (rule evaluation failures, data-gathering
	 * warnings, etc.). Returns an empty array when scoring completed without issues.
	 * @return Array of diagnostics, empty if no issues
	 */
	IScoringDiagnostic[] getDiagnostics();

	/**
	 * A diagnostic message produced during scoring.
	 * Includes optional YAML source location so rule authors can locate problems.
	 */
	interface IScoringDiagnostic {
		/** Severity level of a scoring diagnostic. */
		enum Level {
			/** Non-fatal issue during scoring. */
			WARNING,
			/** Fatal issue during scoring. */
			ERROR
		}

		/** Rule identifier, or null for non-rule diagnostics.
		 * @return rule ID string, or null */
		String getRuleId();
		/** Category key, or null for global diagnostics.
		 * @return category key string, or null */
		String getCategory();
		/** Severity level of this diagnostic.
		 * @return diagnostic level */
		Level getLevel();
		/** Human-readable diagnostic message.
		 * @return message string */
		String getMessage();
		/** 1-based YAML source line, -1 if unknown.
		 * @return line number */
		int getLine();
		/** 1-based YAML source column, -1 if unknown.
		 * @return column number */
		int getColumn();
	}

	/**
	 * Per-category score details.
	 */
	interface ICategoryScore {
		/**
		 * Built-in category enum, or null for custom user-defined categories.
		 * @return Score category enum value, or null
		 */
		ScoreCategory getCategory();
		/** Category sub-score (0-100), computed as average of matched rule scores.
		 * @return category score */
		int getScore();
		/**
		 * Risk level for this category based on its score.
		 * @return Risk level
		 */
		RiskLevel getRiskLevel();
		/**
		 * Human-readable display name for this category.
		 * @return Display name
		 */
		String getDisplayName();
		/**
		 * Summary text describing the category's findings.
		 * @return Summary string
		 */
		String getSummary();
		/**
		 * Individual deductions (matched rules) within this category.
		 * @return Array of deductions, empty if no rules matched
		 */
		IDeduction[] getDeductions();

		/**
		 * String key identifying this category. For built-in categories,
		 * returns the enum name (e.g., "PROTOCOLS"). For custom categories,
		 * returns the YAML key string (e.g., "PCI_COMPLIANCE").
		 * @return Category key string, never null
		 */
		default String getCategoryKey() {
			ScoreCategory cat = getCategory();
			return cat != null ? cat.name() : "UNKNOWN";
		}

		/**
		 * Diagnostics collected during this category's scoring.
		 * @return Array of diagnostics, empty if no issues
		 */
		default IScoringDiagnostic[] getDiagnostics() {
			return new IScoringDiagnostic[0];
		}
	}

	/**
	 * Individual deduction within a category.
	 */
	interface IDeduction {
		/**
		 * Stable rule identifier (e.g., "SYS-0000100").
		 * @return Rule ID string
		 */
		String getRuleId();
		/**
		 * Human-readable description of the finding.
		 * @return Description string
		 */
		String getDescription();
		/** Normalized rule score (0.0-1.0).
		 * @return score value between 0.0 and 1.0 */
		double getScore();
		/** Severity derived from the rule score via severity_mapping.
		 * @return severity string */
		String getSeverity();
		/**
		 * Whether this deduction is inconclusive (data was unavailable to confirm
		 * the finding). Inconclusive deductions still count toward the score but
		 * callers can distinguish verified findings from unverified ones.
		 * @return true if the finding could not be conclusively verified
		 */
		default boolean isInconclusive() { return false; }

		/**
		 * Structured scope metadata indicating which protocol layer, TLS versions,
		 * and specific mechanism this deduction applies to. Returns null when the
		 * rule does not define a scope.
		 * @return Scope metadata, or null
		 */
		default IScope getScope() { return null; }

		/**
		 * Scope metadata for a deduction, describing the protocol layer,
		 * affected TLS versions, and specific mechanism being checked.
		 */
		interface IScope {
			/**
			 * Service/protocol layer (e.g., "tls", "certificate", "revocation",
			 * "http", "dns", "server"). Never null when scope is defined.
			 * @return Layer string
			 */
			String getLayer();

			/**
			 * TLS versions affected by this rule (e.g., "TLSv1.2", "TLSv1.3").
			 * Returns an empty array if the rule is not version-specific.
			 * @return Array of protocol version strings
			 */
			String[] getProtocols();

			/**
			 * Specific mechanism being checked (e.g., "renegotiation", "ocsp", "hsts").
			 * Returns null if not specified.
			 * @return Aspect string, or null
			 */
			String getAspect();
		}
	}
}
