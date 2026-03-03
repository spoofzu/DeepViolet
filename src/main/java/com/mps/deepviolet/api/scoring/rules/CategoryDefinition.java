package com.mps.deepviolet.api.scoring.rules;

import java.util.List;

/**
 * A scoring category parsed from YAML.
 *
 * @param key         Category key (e.g., "PROTOCOLS", "PCI_COMPLIANCE")
 * @param displayName Human-readable display name
 * @param rules       Ordered list of rules in this category
 */
public record CategoryDefinition(
		String key,
		String displayName,
		List<RuleDefinition> rules
) {}
