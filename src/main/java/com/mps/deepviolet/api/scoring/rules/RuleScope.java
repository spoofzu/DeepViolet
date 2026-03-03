package com.mps.deepviolet.api.scoring.rules;

import java.util.List;

/**
 * Structured scope metadata for a scoring rule, indicating which protocol layer,
 * TLS versions, and specific mechanism the rule applies to.
 *
 * @param layer     Service/protocol layer (e.g., "tls", "certificate", "revocation", "http", "dns", "server")
 * @param protocols TLS versions affected (e.g., ["TLSv1.2", "TLSv1.3"]), empty if not version-specific
 * @param aspect    Specific mechanism being checked (e.g., "renegotiation", "ocsp", "hsts"), or null
 */
public record RuleScope(String layer, List<String> protocols, String aspect) {

	public RuleScope {
		if (protocols == null) {
			protocols = List.of();
		}
	}
}
