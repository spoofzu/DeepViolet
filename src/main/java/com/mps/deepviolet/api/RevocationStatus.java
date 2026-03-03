package com.mps.deepviolet.api;

/**
 * Package-private POJO implementation of IRevocationStatus.
 */
class RevocationStatus implements IRevocationStatus {

	private String certSubjectDN;

	// OCSP
	private RevocationResult ocspStatus = RevocationResult.NOT_CHECKED;
	private String ocspResponderUrl;
	private long ocspResponseTimeMs;
	private String ocspThisUpdate;
	private String ocspNextUpdate;
	private boolean ocspSignatureValid;
	private String ocspErrorMessage;

	// CRL
	private RevocationResult crlStatus = RevocationResult.NOT_CHECKED;
	private String crlDistributionPoint;
	private long crlResponseTimeMs;
	private long crlSizeBytes;
	private String crlThisUpdate;
	private String crlNextUpdate;
	private String crlErrorMessage;

	// OCSP Stapling
	private boolean ocspStaplingPresent;
	private RevocationResult stapledOcspStatus = RevocationResult.NOT_CHECKED;

	// Must-Staple
	private boolean mustStaplePresent;

	// OneCRL
	private RevocationResult oneCrlStatus = RevocationResult.NOT_CHECKED;
	private String oneCrlErrorMessage;

	// SCTs - broken down by delivery method
	private int embeddedSctCount;
	private String[] embeddedSctDetails = new String[0];
	private int tlsExtensionSctCount = -1; // -1 means N/A (Java limitation)
	private String[] tlsExtensionSctDetails = new String[0];
	private int ocspStaplingSctCount;
	private String[] ocspStaplingSctDetails = new String[0];

	RevocationStatus(String certSubjectDN) {
		this.certSubjectDN = certSubjectDN;
	}

	// --- Getters ---

	public String getCertSubjectDN() { return certSubjectDN; }

	public RevocationResult getOcspStatus() { return ocspStatus; }
	public String getOcspResponderUrl() { return ocspResponderUrl; }
	public long getOcspResponseTimeMs() { return ocspResponseTimeMs; }
	public String getOcspThisUpdate() { return ocspThisUpdate; }
	public String getOcspNextUpdate() { return ocspNextUpdate; }
	public boolean isOcspSignatureValid() { return ocspSignatureValid; }
	public String getOcspErrorMessage() { return ocspErrorMessage; }

	public RevocationResult getCrlStatus() { return crlStatus; }
	public String getCrlDistributionPoint() { return crlDistributionPoint; }
	public long getCrlResponseTimeMs() { return crlResponseTimeMs; }
	public long getCrlSizeBytes() { return crlSizeBytes; }
	public String getCrlThisUpdate() { return crlThisUpdate; }
	public String getCrlNextUpdate() { return crlNextUpdate; }
	public String getCrlErrorMessage() { return crlErrorMessage; }

	public boolean isOcspStaplingPresent() { return ocspStaplingPresent; }
	public RevocationResult getStapledOcspStatus() { return stapledOcspStatus; }

	public boolean isMustStaplePresent() { return mustStaplePresent; }

	public RevocationResult getOneCrlStatus() { return oneCrlStatus; }
	public String getOneCrlErrorMessage() { return oneCrlErrorMessage; }

	// Total SCT count across all delivery methods
	public int getSctCount() {
		int total = embeddedSctCount + ocspStaplingSctCount;
		// Don't add tlsExtensionSctCount if it's -1 (N/A)
		if (tlsExtensionSctCount > 0) {
			total += tlsExtensionSctCount;
		}
		return total;
	}
	// Legacy: return all SCT details combined
	public String[] getSctDetails() {
		// For backward compatibility, return embedded SCT details
		return embeddedSctDetails;
	}

	// Embedded SCTs (from certificate extension)
	public int getEmbeddedSctCount() { return embeddedSctCount; }
	public String[] getEmbeddedSctDetails() { return embeddedSctDetails; }

	// TLS Extension SCTs (-1 means N/A due to Java limitation)
	public int getTlsExtensionSctCount() { return tlsExtensionSctCount; }
	public String[] getTlsExtensionSctDetails() { return tlsExtensionSctDetails; }

	// OCSP Stapling SCTs
	public int getOcspStaplingSctCount() { return ocspStaplingSctCount; }
	public String[] getOcspStaplingSctDetails() { return ocspStaplingSctDetails; }

	// --- Setters (package-private) ---

	void setOcspStatus(RevocationResult s) { this.ocspStatus = s; }
	void setOcspResponderUrl(String u) { this.ocspResponderUrl = u; }
	void setOcspResponseTimeMs(long t) { this.ocspResponseTimeMs = t; }
	void setOcspThisUpdate(String s) { this.ocspThisUpdate = s; }
	void setOcspNextUpdate(String s) { this.ocspNextUpdate = s; }
	void setOcspSignatureValid(boolean v) { this.ocspSignatureValid = v; }
	void setOcspErrorMessage(String m) { this.ocspErrorMessage = m; }

	void setCrlStatus(RevocationResult s) { this.crlStatus = s; }
	void setCrlDistributionPoint(String u) { this.crlDistributionPoint = u; }
	void setCrlResponseTimeMs(long t) { this.crlResponseTimeMs = t; }
	void setCrlSizeBytes(long s) { this.crlSizeBytes = s; }
	void setCrlThisUpdate(String s) { this.crlThisUpdate = s; }
	void setCrlNextUpdate(String s) { this.crlNextUpdate = s; }
	void setCrlErrorMessage(String m) { this.crlErrorMessage = m; }

	void setOcspStaplingPresent(boolean p) { this.ocspStaplingPresent = p; }
	void setStapledOcspStatus(RevocationResult s) { this.stapledOcspStatus = s; }

	void setMustStaplePresent(boolean p) { this.mustStaplePresent = p; }

	void setOneCrlStatus(RevocationResult s) { this.oneCrlStatus = s; }
	void setOneCrlErrorMessage(String m) { this.oneCrlErrorMessage = m; }

	// Embedded SCT setters
	void setEmbeddedSctCount(int c) { this.embeddedSctCount = c; }
	void setEmbeddedSctDetails(String[] d) { this.embeddedSctDetails = d; }

	// TLS Extension SCT setters
	void setTlsExtensionSctCount(int c) { this.tlsExtensionSctCount = c; }
	void setTlsExtensionSctDetails(String[] d) { this.tlsExtensionSctDetails = d; }

	// OCSP Stapling SCT setters
	void setOcspStaplingSctCount(int c) { this.ocspStaplingSctCount = c; }
	void setOcspStaplingSctDetails(String[] d) { this.ocspStaplingSctDetails = d; }
}
