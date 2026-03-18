package com.mps.deepviolet.persist;

import java.util.Map;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;

/**
 * Per-host data snapshot for scan persistence.
 * Contains all materialized scan data for a single target host.
 *
 * @author Milton Smith
 */
public class HostSnapshot {

	private final String targetUrl;
	private IRiskScore riskScore;
	private ICipherSuite[] ciphers;
	private Map<String, String> securityHeaders;
	private Map<String, String> connProperties;
	private Map<String, String> httpHeaders;
	private String tlsFingerprint;
	private Map<String, Object> reportTree;
	private String errorMessage;
	private Map<String, Object> ruleContextMap;

	/**
	 * Creates a snapshot for the given target URL.
	 *
	 * @param targetUrl the scanned target URL
	 */
	public HostSnapshot(String targetUrl) {
		this.targetUrl = targetUrl;
	}

	/**
	 * Returns the scanned target URL.
	 * @return the scanned target URL
	 */
	public String getTargetUrl() { return targetUrl; }

	/**
	 * Returns the risk score, or {@code null} if not computed.
	 * @return the risk score
	 */
	public IRiskScore getRiskScore() { return riskScore; }

	/**
	 * Sets the risk score.
	 * @param riskScore the risk score
	 */
	public void setRiskScore(IRiskScore riskScore) { this.riskScore = riskScore; }

	/**
	 * Returns the cipher suites, or {@code null} if not enumerated.
	 * @return the cipher suites
	 */
	public ICipherSuite[] getCiphers() { return ciphers; }

	/**
	 * Sets the cipher suites.
	 * @param ciphers the cipher suites
	 */
	public void setCiphers(ICipherSuite[] ciphers) { this.ciphers = ciphers; }

	/**
	 * Returns the security headers map.
	 * @return the security headers
	 */
	public Map<String, String> getSecurityHeaders() { return securityHeaders; }

	/**
	 * Sets the security headers.
	 * @param securityHeaders the security headers
	 */
	public void setSecurityHeaders(Map<String, String> securityHeaders) {
		this.securityHeaders = securityHeaders;
	}

	/**
	 * Returns the connection properties map.
	 * @return the connection properties
	 */
	public Map<String, String> getConnProperties() { return connProperties; }

	/**
	 * Sets the connection properties.
	 * @param connProperties the connection properties
	 */
	public void setConnProperties(Map<String, String> connProperties) {
		this.connProperties = connProperties;
	}

	/**
	 * Returns the HTTP response headers map.
	 * @return the HTTP headers
	 */
	public Map<String, String> getHttpHeaders() { return httpHeaders; }

	/**
	 * Sets the HTTP response headers.
	 * @param httpHeaders the HTTP headers
	 */
	public void setHttpHeaders(Map<String, String> httpHeaders) {
		this.httpHeaders = httpHeaders;
	}

	/**
	 * Returns the 62-character TLS server fingerprint, or {@code null}.
	 * @return the TLS fingerprint
	 */
	public String getTlsFingerprint() { return tlsFingerprint; }

	/**
	 * Sets the TLS server fingerprint.
	 * @param tlsFingerprint the fingerprint
	 */
	public void setTlsFingerprint(String tlsFingerprint) {
		this.tlsFingerprint = tlsFingerprint;
	}

	/**
	 * Returns the structured report tree.
	 * @return the report tree
	 */
	public Map<String, Object> getReportTree() { return reportTree; }

	/**
	 * Sets the structured report tree.
	 * @param reportTree the report tree
	 */
	public void setReportTree(Map<String, Object> reportTree) {
		this.reportTree = reportTree;
	}

	/**
	 * Returns the error message, or {@code null} if the scan succeeded.
	 * @return the error message
	 */
	public String getErrorMessage() { return errorMessage; }

	/**
	 * Sets the error message.
	 * @param errorMessage the error message
	 */
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	/**
	 * Returns the rule context map used for risk scoring.
	 * @return the rule context map
	 */
	public Map<String, Object> getRuleContextMap() { return ruleContextMap; }

	/**
	 * Sets the rule context map.
	 * @param ruleContextMap the rule context map
	 */
	public void setRuleContextMap(Map<String, Object> ruleContextMap) {
		this.ruleContextMap = ruleContextMap;
	}

	/**
	 * Returns {@code true} if no error was recorded for this host.
	 * @return true if no error was recorded
	 */
	public boolean isSuccess() { return errorMessage == null; }
}
