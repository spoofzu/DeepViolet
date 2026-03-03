package com.mps.deepviolet.api;

/**
 * Revocation and transparency status for a certificate.
 * Covers OCSP, CRL, OCSP Stapling, OneCRL, Must-Staple, and Certificate Transparency SCTs.
 *
 * @author Milton Smith
 */
public interface IRevocationStatus {

	enum RevocationResult {
		GOOD, REVOKED, UNKNOWN, ERROR, NOT_CHECKED
	}

	// --- OCSP ---

	/**
	 * OCSP revocation check result.
	 * @return GOOD, REVOKED, UNKNOWN, ERROR, or NOT_CHECKED
	 */
	RevocationResult getOcspStatus();

	/**
	 * URL of the OCSP responder queried.
	 * @return Responder URL, or null if not available
	 */
	String getOcspResponderUrl();

	/**
	 * Time taken for the OCSP query in milliseconds.
	 * @return Response time, or -1 if not measured
	 */
	long getOcspResponseTimeMs();

	/**
	 * OCSP response thisUpdate timestamp.
	 * @return Timestamp string, or null if unavailable
	 */
	String getOcspThisUpdate();

	/**
	 * OCSP response nextUpdate timestamp.
	 * @return Timestamp string, or null if unavailable
	 */
	String getOcspNextUpdate();

	/**
	 * Whether the OCSP response signature was validated.
	 * @return true if signature is valid
	 */
	boolean isOcspSignatureValid();

	/**
	 * Error message from the OCSP check, if any.
	 * @return Error message, or null on success
	 */
	String getOcspErrorMessage();

	// --- CRL ---

	/**
	 * CRL revocation check result.
	 * @return GOOD, REVOKED, UNKNOWN, ERROR, or NOT_CHECKED
	 */
	RevocationResult getCrlStatus();

	/**
	 * CRL distribution point URL that was queried.
	 * @return Distribution point URL, or null if not available
	 */
	String getCrlDistributionPoint();

	/**
	 * Time taken to download and check the CRL in milliseconds.
	 * @return Response time, or -1 if not measured
	 */
	long getCrlResponseTimeMs();

	/**
	 * Size of the downloaded CRL in bytes.
	 * @return CRL size, or -1 if not downloaded
	 */
	long getCrlSizeBytes();

	/**
	 * CRL thisUpdate timestamp.
	 * @return Timestamp string, or null if unavailable
	 */
	String getCrlThisUpdate();

	/**
	 * CRL nextUpdate timestamp.
	 * @return Timestamp string, or null if unavailable
	 */
	String getCrlNextUpdate();

	/**
	 * Error message from the CRL check, if any.
	 * @return Error message, or null on success
	 */
	String getCrlErrorMessage();

	// --- OCSP Stapling ---

	/**
	 * Whether an OCSP stapled response was present in the TLS handshake.
	 * @return true if stapled response was captured
	 */
	boolean isOcspStaplingPresent();

	/**
	 * Status from the stapled OCSP response.
	 * @return GOOD, REVOKED, UNKNOWN, ERROR, or NOT_CHECKED
	 */
	RevocationResult getStapledOcspStatus();

	// --- Must-Staple ---

	/**
	 * Whether the certificate contains the Must-Staple TLS Feature extension
	 * (OID 1.3.6.1.4.1.5.5.7.1.24).
	 * @return true if Must-Staple is present
	 */
	boolean isMustStaplePresent();

	// --- OneCRL ---

	/**
	 * Mozilla OneCRL revocation check result.
	 * @return GOOD, REVOKED, UNKNOWN, ERROR, or NOT_CHECKED
	 */
	RevocationResult getOneCrlStatus();

	/**
	 * Error message from the OneCRL check, if any.
	 * @return Error message, or null on success
	 */
	String getOneCrlErrorMessage();

	// --- Certificate Transparency SCTs ---

	/**
	 * Total SCT count across all delivery methods.
	 * @return Total count of embedded + TLS extension + OCSP stapling SCTs
	 */
	int getSctCount();

	/**
	 * Details for all SCTs (legacy, for backward compatibility).
	 * @return Array of SCT detail strings
	 */
	String[] getSctDetails();

	/**
	 * Count of SCTs embedded in the certificate (OID 1.3.6.1.4.1.11129.2.4.2).
	 * @return Number of embedded SCTs, or 0 if none
	 */
	int getEmbeddedSctCount();

	/**
	 * Details for each embedded SCT.
	 * @return Array of SCT detail strings
	 */
	String[] getEmbeddedSctDetails();

	/**
	 * Count of SCTs delivered via TLS extension (type 18).
	 * @return Number of TLS extension SCTs, or -1 if not available (Java limitation)
	 */
	int getTlsExtensionSctCount();

	/**
	 * Details for each TLS extension SCT.
	 * @return Array of SCT detail strings, or empty if N/A
	 */
	String[] getTlsExtensionSctDetails();

	/**
	 * Count of SCTs delivered via OCSP stapling response (OID 1.3.6.1.4.1.11129.2.4.5).
	 * @return Number of OCSP stapling SCTs, or 0 if none
	 */
	int getOcspStaplingSctCount();

	/**
	 * Details for each OCSP stapling SCT.
	 * @return Array of SCT detail strings
	 */
	String[] getOcspStaplingSctDetails();

	// --- Identity ---

	/**
	 * Subject DN of the certificate that was checked.
	 * @return Certificate subject distinguished name
	 */
	String getCertSubjectDN();
}
