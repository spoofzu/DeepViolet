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

	public HostSnapshot(String targetUrl) {
		this.targetUrl = targetUrl;
	}

	public String getTargetUrl() { return targetUrl; }

	public IRiskScore getRiskScore() { return riskScore; }
	public void setRiskScore(IRiskScore riskScore) { this.riskScore = riskScore; }

	public ICipherSuite[] getCiphers() { return ciphers; }
	public void setCiphers(ICipherSuite[] ciphers) { this.ciphers = ciphers; }

	public Map<String, String> getSecurityHeaders() { return securityHeaders; }
	public void setSecurityHeaders(Map<String, String> securityHeaders) {
		this.securityHeaders = securityHeaders;
	}

	public Map<String, String> getConnProperties() { return connProperties; }
	public void setConnProperties(Map<String, String> connProperties) {
		this.connProperties = connProperties;
	}

	public Map<String, String> getHttpHeaders() { return httpHeaders; }
	public void setHttpHeaders(Map<String, String> httpHeaders) {
		this.httpHeaders = httpHeaders;
	}

	public String getTlsFingerprint() { return tlsFingerprint; }
	public void setTlsFingerprint(String tlsFingerprint) {
		this.tlsFingerprint = tlsFingerprint;
	}

	public Map<String, Object> getReportTree() { return reportTree; }
	public void setReportTree(Map<String, Object> reportTree) {
		this.reportTree = reportTree;
	}

	public String getErrorMessage() { return errorMessage; }
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public Map<String, Object> getRuleContextMap() { return ruleContextMap; }
	public void setRuleContextMap(Map<String, Object> ruleContextMap) {
		this.ruleContextMap = ruleContextMap;
	}

	public boolean isSuccess() { return errorMessage == null; }
}
