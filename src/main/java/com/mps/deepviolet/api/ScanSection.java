package com.mps.deepviolet.api;

/**
 * Defines the discrete phases of a host scan.
 * Each section maps to a real operation in DeepVioletEngine/CipherSuiteUtil.
 *
 * @author Milton Smith
 */
public enum ScanSection {

	SESSION_INIT("Session initialization"),
	CIPHER_ENUMERATION("Cipher suite enumeration"),
	CERTIFICATE_RETRIEVAL("Certificate retrieval"),
	RISK_SCORING("Risk scoring"),
	TLS_FINGERPRINT("TLS fingerprinting"),
	DNS_SECURITY("DNS security check"),
	REVOCATION_CHECK("Revocation check");

	private final String displayName;

	ScanSection(String displayName) {
		this.displayName = displayName;
	}

	/**
	 * Human-readable display name for this scan section.
	 * @return display name
	 */
	public String getDisplayName() {
		return displayName;
	}
}
