package com.mps.deepviolet.api;

/**
 * Defines the discrete phases of a host scan.
 * Each section maps to a real operation in DeepVioletEngine/CipherSuiteUtil.
 *
 * @author Milton Smith
 */
public enum ScanSection {

	/** Initialize TLS session and capture metadata. */
	SESSION_INIT("Session initialization"),
	/** Enumerate supported cipher suites. */
	CIPHER_ENUMERATION("Cipher suite enumeration"),
	/** Retrieve X.509 certificate chain. */
	CERTIFICATE_RETRIEVAL("Certificate retrieval"),
	/** Compute TLS risk score. */
	RISK_SCORING("Risk scoring"),
	/** Compute TLS probe fingerprint. */
	TLS_FINGERPRINT("TLS probe fingerprinting"),
	/** Check DNS security (CAA, DANE/TLSA). */
	DNS_SECURITY("DNS security check"),
	/** Check certificate revocation status. */
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
