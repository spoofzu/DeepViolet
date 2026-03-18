package com.mps.deepviolet.api.scoring.rules;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;
import org.snakeyaml.engine.v2.api.lowlevel.Compose;
import org.snakeyaml.engine.v2.nodes.MappingNode;
import org.snakeyaml.engine.v2.nodes.Node;
import org.snakeyaml.engine.v2.nodes.NodeTuple;
import org.snakeyaml.engine.v2.nodes.ScalarNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.IRiskScore.LetterGrade;
import com.mps.deepviolet.api.IRiskScore.RiskLevel;

/**
 * Parses a YAML rule policy file into a {@link RulePolicy} with pre-parsed expressions.
 */
public class RulePolicyLoader {

	/** Default constructor. */
	public RulePolicyLoader() {}

	private static final Logger logger = LoggerFactory.getLogger(RulePolicyLoader.class);
	private static final String DEFAULT_RESOURCE = "risk-scoring-rules.yaml";
	private static final String SYSTEM_PROPERTY = "dv.scoring.rules";

	/**
	 * Try to load a YAML rule policy. Returns null if no YAML rules are available.
	 * <ol>
	 *   <li>System property {@code dv.scoring.rules} → load from file path</li>
	 *   <li>Classpath {@code risk-scoring-rules.yaml} → load from bundled resource</li>
	 *   <li>Neither present → return null (fall back to hardcoded scorers)</li>
	 * </ol>
	 * @return loaded rule policy, or null if no YAML rules are available
	 */
	public static RulePolicy tryLoad() {
		String externalPath = System.getProperty(SYSTEM_PROPERTY);
		if (externalPath != null && !externalPath.isEmpty()) {
			logger.info("Loading YAML rules from system property: {}", externalPath);
			return loadFromFile(externalPath);
		}
		try (InputStream is = RulePolicyLoader.class.getClassLoader()
				.getResourceAsStream(DEFAULT_RESOURCE)) {
			if (is != null) {
				logger.info("Loading YAML rules from classpath: {}", DEFAULT_RESOURCE);
				return loadFromStream(is, DEFAULT_RESOURCE);
			}
		} catch (IOException e) {
			logger.warn("Error reading YAML rules from classpath: {}", e.getMessage());
		}
		return null;
	}

	/**
	 * Load a rule policy from a file path.
	 * @param path file system path
	 * @return loaded rule policy
	 */
	public static RulePolicy loadFromFile(String path) {
		try (InputStream is = Files.newInputStream(Path.of(path))) {
			return loadFromStream(is, path);
		} catch (IOException e) {
			throw new IllegalArgumentException("Failed to load YAML rules from file: " + path, e);
		}
	}

	/**
	 * Load a rule policy from an input stream (source file unknown).
	 * @param is input stream
	 * @return loaded rule policy
	 */
	public static RulePolicy loadFromStream(InputStream is) {
		return loadFromStream(is, null);
	}

	/**
	 * Load a rule policy from an input stream with a known source filename.
	 * @param is input stream
	 * @param sourceFile source file name for diagnostics
	 * @return loaded rule policy
	 */
	@SuppressWarnings("unchecked")
	public static RulePolicy loadFromStream(InputStream is, String sourceFile) {
		// Read stream into byte[] so we can parse twice
		byte[] yamlBytes;
		try {
			yamlBytes = is.readAllBytes();
		} catch (IOException e) {
			throw new IllegalArgumentException("Failed to read YAML input", e);
		}

		// First parse: data extraction via Load (existing logic)
		LoadSettings settings = LoadSettings.builder().build();
		Load load = new Load(settings);
		Map<String, Object> root = (Map<String, Object>) load.loadFromInputStream(
				new ByteArrayInputStream(yamlBytes));

		// Second parse: Compose to get Node tree with source marks
		Map<String, Map<String, int[]>> sourceLocations = extractSourceLocations(yamlBytes);

		// Metadata
		Map<String, Object> metadata = getMap(root, "metadata");
		String version = metadata != null ? getString(metadata, "version", "1.0") : "1.0";

		// Severity mapping
		List<Map<String, Object>> severityMappingList = getList(root, "severity_mapping");
		List<RulePolicy.SeverityMapping> severityMappings = new ArrayList<>();
		if (severityMappingList != null) {
			for (Map<String, Object> entry : severityMappingList) {
				String severity = getString(entry, "severity", "LOW");
				double minScore = getDouble(entry, "min_score", 0.0);
				int floor = getInt(entry, "floor", 100);
				severityMappings.add(new RulePolicy.SeverityMapping(severity, minScore, floor));
			}
		}

		// Grade mapping
		List<Map<String, Object>> gradeMappingList = getList(root, "grade_mapping");
		List<RulePolicy.GradeMapping> gradeMappings = new ArrayList<>();
		if (gradeMappingList != null) {
			for (Map<String, Object> entry : gradeMappingList) {
				LetterGrade grade = LetterGrade.valueOf(getString(entry, "grade", "F"));
				int minScore = getInt(entry, "min_score", 0);
				RiskLevel riskLevel = RiskLevel.valueOf(getString(entry, "risk_level", "CRITICAL"));
				gradeMappings.add(new RulePolicy.GradeMapping(grade, minScore, riskLevel));
			}
		}

		// Categories
		Map<String, Object> categoriesMap = getMap(root, "categories");
		List<CategoryDefinition> categories = new ArrayList<>();
		if (categoriesMap != null) {
			for (Map.Entry<String, Object> catEntry : categoriesMap.entrySet()) {
				String catKey = catEntry.getKey();
				Map<String, Object> catMap = (Map<String, Object>) catEntry.getValue();
				String displayName = getString(catMap, "display_name", catKey);

				// Get source locations for this category's rules
				Map<String, int[]> catLocations = sourceLocations.getOrDefault(catKey, Map.of());

				// Rules
				Map<String, Object> rulesMap = getMap(catMap, "rules");
				List<RuleDefinition> rules = new ArrayList<>();
				if (rulesMap != null) {
					for (Map.Entry<String, Object> ruleEntry : rulesMap.entrySet()) {
						String ruleId = ruleEntry.getKey();
						Map<String, Object> ruleMap = (Map<String, Object>) ruleEntry.getValue();
						int[] loc = catLocations.getOrDefault(ruleId, new int[]{-1, -1});
						rules.add(parseRule(ruleId, ruleMap, loc[0], loc[1]));
					}
				}

				categories.add(new CategoryDefinition(catKey, displayName, rules));
			}
		}

		return new RulePolicy(version, severityMappings, gradeMappings, categories, sourceFile);
	}

	/**
	 * Extract source line/column for each rule key using the SnakeYAML Compose API.
	 * Returns categoryKey → ruleId → [line (1-based), column (1-based)].
	 */
	private static Map<String, Map<String, int[]>> extractSourceLocations(byte[] yamlBytes) {
		Map<String, Map<String, int[]>> result = new HashMap<>();
		try {
			LoadSettings composeSettings = LoadSettings.builder().build();
			Compose compose = new Compose(composeSettings);
			Optional<Node> rootNodeOpt = compose.composeInputStream(
					new ByteArrayInputStream(yamlBytes));
			if (rootNodeOpt.isEmpty() || !(rootNodeOpt.get() instanceof MappingNode rootMapping)) {
				return result;
			}

			// Find the "categories" key in root mapping
			Node categoriesNode = findValueNode(rootMapping, "categories");
			if (!(categoriesNode instanceof MappingNode categoriesMapping)) {
				return result;
			}

			// Iterate each category
			for (NodeTuple catTuple : categoriesMapping.getValue()) {
				if (!(catTuple.getKeyNode() instanceof ScalarNode catKeyNode)) continue;
				String catKey = catKeyNode.getValue();

				if (!(catTuple.getValueNode() instanceof MappingNode catMapping)) continue;

				// Find the "rules" key within this category
				Node rulesNode = findValueNode(catMapping, "rules");
				if (!(rulesNode instanceof MappingNode rulesMapping)) continue;

				Map<String, int[]> ruleLocations = new HashMap<>();
				for (NodeTuple ruleTuple : rulesMapping.getValue()) {
					if (!(ruleTuple.getKeyNode() instanceof ScalarNode ruleKeyNode)) continue;
					String ruleId = ruleKeyNode.getValue();

					// SnakeYAML marks are 0-based; convert to 1-based
					int line = ruleKeyNode.getStartMark()
							.map(m -> m.getLine() + 1).orElse(-1);
					int column = ruleKeyNode.getStartMark()
							.map(m -> m.getColumn() + 1).orElse(-1);
					ruleLocations.put(ruleId, new int[]{line, column});
				}
				result.put(catKey, ruleLocations);
			}
		} catch (Exception e) {
			logger.debug("Could not extract YAML source locations: {}", e.getMessage());
		}
		return result;
	}

	/**
	 * Find the value Node for a given key in a MappingNode.
	 */
	private static Node findValueNode(MappingNode mapping, String key) {
		for (NodeTuple tuple : mapping.getValue()) {
			if (tuple.getKeyNode() instanceof ScalarNode scalar
					&& key.equals(scalar.getValue())) {
				return tuple.getValueNode();
			}
		}
		return null;
	}

	/**
	 * Load user-defined rules from an input stream.
	 * The YAML must contain only a {@code categories} key with rules using {@code USR-} prefixed IDs.
	 * No {@code metadata}, {@code severity_mapping}, or {@code grade_mapping} keys are expected.
	 *
	 * @param is InputStream containing user rules YAML
	 * @return RulePolicy with version "user", empty severity/grade mappings, and the parsed categories
	 * @throws IllegalArgumentException if validation fails (missing id, wrong prefix, etc.)
	 */
	@SuppressWarnings("unchecked")
	public static RulePolicy loadUserRules(InputStream is) {
		byte[] yamlBytes;
		try {
			yamlBytes = is.readAllBytes();
		} catch (IOException e) {
			throw new IllegalArgumentException("Failed to read user rules YAML input", e);
		}

		LoadSettings settings = LoadSettings.builder().build();
		Load load = new Load(settings);
		Map<String, Object> root = (Map<String, Object>) load.loadFromInputStream(
				new ByteArrayInputStream(yamlBytes));

		Map<String, Map<String, int[]>> sourceLocations = extractSourceLocations(yamlBytes);

		Map<String, Object> categoriesMap = getMap(root, "categories");
		if (categoriesMap == null || categoriesMap.isEmpty()) {
			throw new IllegalArgumentException("User rules YAML must contain a 'categories' key with at least one category");
		}

		List<CategoryDefinition> categories = new ArrayList<>();
		for (Map.Entry<String, Object> catEntry : categoriesMap.entrySet()) {
			String catKey = catEntry.getKey();
			Map<String, Object> catMap = (Map<String, Object>) catEntry.getValue();
			String displayName = getString(catMap, "display_name", catKey);

			Map<String, int[]> catLocations = sourceLocations.getOrDefault(catKey, Map.of());

			Map<String, Object> rulesMap = getMap(catMap, "rules");
			List<RuleDefinition> rules = new ArrayList<>();
			if (rulesMap != null) {
				for (Map.Entry<String, Object> ruleEntry : rulesMap.entrySet()) {
					String ruleId = ruleEntry.getKey();
					Map<String, Object> ruleMap = (Map<String, Object>) ruleEntry.getValue();
					int[] loc = catLocations.getOrDefault(ruleId, new int[]{-1, -1});

					// Validate id is present and has USR- prefix
					String id = getString(ruleMap, "id", null);
					if (id == null || id.isBlank()) {
						throw new IllegalArgumentException(
								"User rule '" + ruleId + "' in category '" + catKey + "' must have an 'id' field");
					}
					if (id.startsWith("SYS-")) {
						throw new IllegalArgumentException(
								"User rule '" + ruleId + "' has id '" + id + "' with SYS- prefix; user rules must use USR- prefix");
					}
					if (!id.startsWith("USR-")) {
						throw new IllegalArgumentException(
								"User rule '" + ruleId + "' has id '" + id + "'; user rule IDs must start with USR-");
					}

					rules.add(parseRule(ruleId, ruleMap, loc[0], loc[1]));
				}
			}

			categories.add(new CategoryDefinition(catKey, displayName, rules));
		}

		return new RulePolicy("user", List.of(), List.of(), categories);
	}

	private static RuleDefinition parseRule(String ruleId, Map<String, Object> ruleMap,
			int sourceLine, int sourceColumn) {
		String id = getString(ruleMap, "id", null);
		String description = getString(ruleMap, "description", ruleId);
		double score = getDouble(ruleMap, "score", 0.0);
		boolean enabled = getBoolean(ruleMap, "enabled", true);
		boolean inconclusive = getBoolean(ruleMap, "inconclusive", false);

		String locationPrefix = sourceLine > 0
				? sourceLine + ":" + sourceColumn + " "
				: "";

		String whenStr = getString(ruleMap, "when", null);
		RuleExpression when = null;
		if (whenStr != null && !whenStr.isBlank()) {
			try {
				when = RuleExpressionParser.parse(whenStr);
			} catch (IllegalArgumentException e) {
				logger.error("Failed to parse 'when' expression for rule '{}': {}", ruleId, e.getMessage());
				throw new IllegalArgumentException(
						locationPrefix + "Invalid 'when' expression for rule '" + ruleId + "': " + e.getMessage(), e);
			}
		}

		String whenIncStr = getString(ruleMap, "when_inconclusive", null);
		RuleExpression whenInconclusive = null;
		if (whenIncStr != null && !whenIncStr.isBlank()) {
			try {
				whenInconclusive = RuleExpressionParser.parse(whenIncStr);
			} catch (IllegalArgumentException e) {
				logger.error("Failed to parse 'when_inconclusive' expression for rule '{}': {}", ruleId, e.getMessage());
				throw new IllegalArgumentException(
						locationPrefix + "Invalid 'when_inconclusive' expression for rule '" + ruleId + "': " + e.getMessage(), e);
			}
		}

		Map<String, RuleExpression> meta;
		Map<String, Object> metaMap = getMap(ruleMap, "meta");
		if (metaMap != null && !metaMap.isEmpty()) {
			meta = new java.util.LinkedHashMap<>();
			for (Map.Entry<String, Object> metaEntry : metaMap.entrySet()) {
				String varName = metaEntry.getKey();
				String exprStr = metaEntry.getValue() != null ? metaEntry.getValue().toString() : null;
				if (exprStr != null && !exprStr.isBlank()) {
					try {
						meta.put(varName, RuleExpressionParser.parse(exprStr));
					} catch (IllegalArgumentException e) {
						logger.error("Failed to parse 'meta.{}' expression for rule '{}': {}", varName, ruleId, e.getMessage());
						throw new IllegalArgumentException(
								locationPrefix + "Invalid 'meta." + varName + "' expression for rule '" + ruleId + "': " + e.getMessage(), e);
					}
				}
			}
			meta = java.util.Collections.unmodifiableMap(meta);
		} else {
			meta = Map.of();
		}

		// Parse scope metadata
		RuleScope scope = null;
		Map<String, Object> scopeMap = getMap(ruleMap, "scope");
		if (scopeMap != null && !scopeMap.isEmpty()) {
			String layer = getString(scopeMap, "layer", null);
			String aspect = getString(scopeMap, "aspect", null);
			List<String> protocols;
			Object protocolsObj = scopeMap.get("protocols");
			if (protocolsObj instanceof List<?> protocolsList) {
				protocols = protocolsList.stream()
						.map(Object::toString)
						.toList();
			} else {
				protocols = List.of();
			}
			scope = new RuleScope(layer, protocols, aspect);
		}

		return new RuleDefinition(id, ruleId, description, score, enabled, inconclusive,
				when, whenInconclusive, meta, scope, sourceLine, sourceColumn);
	}

	// --- YAML map access helpers ---

	@SuppressWarnings("unchecked")
	private static Map<String, Object> getMap(Map<String, Object> map, String key) {
		Object val = map.get(key);
		if (val instanceof Map) {
			return (Map<String, Object>) val;
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> getList(Map<String, Object> map, String key) {
		Object val = map.get(key);
		if (val instanceof List) {
			return (List<Map<String, Object>>) val;
		}
		return null;
	}

	private static String getString(Map<String, Object> map, String key, String defaultVal) {
		Object val = map.get(key);
		return val != null ? val.toString() : defaultVal;
	}

	private static int getInt(Map<String, Object> map, String key, int defaultVal) {
		Object val = map.get(key);
		if (val instanceof Number n) return n.intValue();
		if (val instanceof String s) {
			try { return Integer.parseInt(s); } catch (NumberFormatException e) { /* fall through */ }
		}
		return defaultVal;
	}

	private static double getDouble(Map<String, Object> map, String key, double defaultVal) {
		Object val = map.get(key);
		if (val instanceof Number n) return n.doubleValue();
		if (val instanceof String s) {
			try { return Double.parseDouble(s); } catch (NumberFormatException e) { /* fall through */ }
		}
		return defaultVal;
	}

	private static boolean getBoolean(Map<String, Object> map, String key, boolean defaultVal) {
		Object val = map.get(key);
		if (val instanceof Boolean b) return b;
		if (val instanceof String s) return Boolean.parseBoolean(s);
		return defaultVal;
	}
}
