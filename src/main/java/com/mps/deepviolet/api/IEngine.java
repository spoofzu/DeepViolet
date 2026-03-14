package com.mps.deepviolet.api;

import java.io.InputStream;
import java.util.List;

import com.mps.deepviolet.api.ai.AiConfig;
import com.mps.deepviolet.api.scoring.rules.RuleContext;

/**
 * Interface specification for engine features available
 * from an initialized host.
 * @author Milton Smith
 *
 */
public interface IEngine {
	
	/**
	 * Return ciphersuites for the target host.  Calls <code>getCipherSuites(CIPHER_NAME_CONVENTION CIPHER_NAME_CONVENTION)</code> with
	 * CIPHER_NAME_CONVENTION.IANA as the default.
	 * @return Ciphersuites supported by target host.
	 * @throws DeepVioletException thrown on problems fetching ciphersuites.
	 */
	ICipherSuite[] getCipherSuites() throws DeepVioletException;	

	/**
	 * Return session instance for the target host when IEngine
	 * was created.
	 * @return Session instance for target host.
	 * @see <a href="DeepVioletFactory.html#initializeSession(URL)">DeepVioletFactory.initializeSession(URL)</a>
	 */
	ISession getSession();

	/**
	 * Write PEM encoded X.509 certificate for the target
	 * host when IEngine was created to a fully qualified
	 * file name.
	 * @param file Fully qualified file name
	 * @return Returns the number of bytes written to disk
	 * @throws DeepVioletException Thrown on problems writing to the disk.
	 */
	long writeCertificate(String file) throws DeepVioletException;
	
	/**
	 * Retrieve a IX509Certificate.
	 * @return Return IX509Certificate representing host associated
	 * with IEngine instance.
	 * @throws DeepVioletException Thrown on problems reading certificate.
	 */
	IX509Certificate getCertificate() throws DeepVioletException;
	
	/**
	 * Return the Major Version of DeepViolet.  Incremented upon significant
	 * addition of new features.  Existing features could also break code.
	 * Callers are urged to test upon implementing new major versions.
	 * @return Number indicating DeepViolet Major Version.
	 */
	int getDeepVioletMajorVersion();

	/**
	 * Return the Minor Version of DeepViolet.  Incremented upon significant
	 * improvement to existing features.   Callers are urged to test upon
	 * implementing new major versions.
	 * @return Number indicating DeepViolet Minor Version.
	 */
	int getDeepVioletMinorVersion();

	/**
	 * Return the Build Version of DeepViolet.  Incremented on bug fixes to
	 * existing features.  It's not anticipated this any improvements will
	 * break code.  Callers are urged to perform basic unit tests.
	 * @return Number indicating DeepViolet Build Version.
	 */
	int getDeepVioletBuildVersion();

	/**
	 * Return the DeepViolet version string.  
	 * @return Suitable for printing in log files, displaying in About boxes, etc.
	 */
	String getDeepVioletStringVersion();
	
	/**
	 * Return Maven SNAPSHOT release status
	 * @return true, DeepViolet is beta status.  false, DeepViolet is release status.
	 */
	boolean isDeepVioletSnapShot();

	/**
	 * Compute TLS server fingerprint for the target host.
	 *
	 * <p>TLS server fingerprinting analyzes how a server responds to 10 different
	 * ClientHello probes to create a 62-character fingerprint that characterizes
	 * the server's TLS selection behavior.</p>
	 *
	 * <p><b>What Fingerprints Identify</b></p>
	 * <ul>
	 *   <li>Server's cipher selection behavior</li>
	 *   <li>Extension ordering in responses</li>
	 *   <li>TLS version negotiation patterns</li>
	 *   <li>Deployment-specific configuration</li>
	 * </ul>
	 *
	 * <p><b>What Fingerprints Do NOT Identify</b></p>
	 * <ul>
	 *   <li>Specific software (nginx, Apache, etc.)</li>
	 *   <li>Software version</li>
	 *   <li>Underlying OS</li>
	 * </ul>
	 *
	 * <p>Technique inspired by Salesforce's JARM.</p>
	 *
	 * @return 62-character TLS fingerprint, or null if unavailable
	 * @throws DeepVioletException Thrown on problems computing fingerprint
	 * @see com.mps.deepviolet.api.fingerprint.TlsServerFingerprint
	 */
	String getTlsFingerprint() throws DeepVioletException;

	/**
	 * Get Signed Certificate Timestamps (SCTs) from the TLS connection.
	 * SCTs can come from three sources:
	 * 1. TLS extension in ServerHello
	 * 2. X.509 certificate extension
	 * 3. OCSP stapled response
	 * @return List of raw SCT bytes from all sources, empty list if none found
	 * @throws DeepVioletException Thrown on problems extracting SCTs
	 */
	List<byte[]> getSCTs() throws DeepVioletException;

	/**
	 * Get detailed TLS metadata from the connection using raw TLS parsing.
	 * This provides access to full ServerHello extensions, fingerprint codes, etc.
	 * @return TLS metadata, or null if raw parsing was not performed
	 * @throws DeepVioletException Thrown on problems getting metadata
	 */
	com.mps.deepviolet.api.tls.TlsMetadata getTlsMetadata() throws DeepVioletException;

	/**
	 * Test whether the server supports TLS_FALLBACK_SCSV (RFC 7507).
	 * @return true if SCSV is supported, false if not, null if test was inconclusive
	 * @throws DeepVioletException Thrown on problems performing the test
	 */
	Boolean getFallbackScsvSupported() throws DeepVioletException;

	/**
	 * Get DNS security status for the target host.
	 * Checks for CAA and DANE/TLSA records.
	 * @return DNS security status, or null if check was not performed
	 * @throws DeepVioletException Thrown on problems checking DNS
	 */
	IDnsStatus getDnsStatus() throws DeepVioletException;

	/**
	 * Build a RuleContext from the current engine state (for persistence).
	 * The returned context can be serialized and later used for offline
	 * re-scoring without re-scanning.
	 *
	 * @return RuleContext snapshot of the current engine state
	 * @throws DeepVioletException Thrown on problems building the context
	 */
	RuleContext buildRuleContext() throws DeepVioletException;

	/**
	 * Compute risk score from a pre-built RuleContext (offline re-scoring).
	 * Uses the default bundled scoring policy.
	 *
	 * @param context pre-built or deserialized RuleContext
	 * @return Risk score with per-category breakdowns and letter grade
	 * @throws DeepVioletException Thrown on problems computing score
	 */
	IRiskScore getRiskScore(RuleContext context) throws DeepVioletException;

	/**
	 * Compute risk score from a pre-built RuleContext with user rules
	 * merged into the system policy.
	 *
	 * @param context pre-built or deserialized RuleContext
	 * @param userRulesStream InputStream containing user rules YAML
	 * @return Risk score with per-category breakdowns and letter grade
	 * @throws DeepVioletException Thrown on problems computing score
	 */
	IRiskScore getRiskScore(RuleContext context, InputStream userRulesStream) throws DeepVioletException;

	/**
	 * Compute a TLS risk score using the default bundled scoring policy.
	 * Evaluates 6 categories (protocols, ciphers, certificate, revocation,
	 * security headers, other) totaling 100 points.
	 * @return Risk score with per-category breakdowns and letter grade
	 * @throws DeepVioletException Thrown on problems computing score
	 */
	IRiskScore getRiskScore() throws DeepVioletException;

	/**
	 * Compute a TLS risk score using a custom YAML rules file.
	 * @param rulesPath Path to custom risk-scoring-rules.yaml file
	 * @return Risk score with per-category breakdowns and letter grade
	 * @throws DeepVioletException Thrown on problems computing score
	 */
	IRiskScore getRiskScore(String rulesPath) throws DeepVioletException;

	/**
	 * Compute risk score using the default system rules merged with
	 * user-defined rules from the given stream. The stream should contain
	 * only categories with USR- prefixed rule IDs.
	 *
	 * @param userRulesStream InputStream containing user rules YAML
	 * @return Risk score with per-category breakdowns and letter grade
	 * @throws DeepVioletException Thrown on problems computing score
	 */
	IRiskScore getRiskScore(InputStream userRulesStream) throws DeepVioletException;

	/**
	 * Analyze the current TLS scan results using an AI provider.
	 * Builds a plain text report from the engine state and sends it
	 * as an InputStream to the AI service.
	 *
	 * @param config AI configuration
	 * @return AI analysis text
	 * @throws DeepVioletException on scan data or AI errors
	 */
	String getAiAnalysis(AiConfig config) throws DeepVioletException;

	/**
	 * Analyze scan data from a caller-provided stream using an AI provider.
	 * The caller controls the data source — file, URL, in-memory buffer, etc.
	 *
	 * @param scanReport InputStream providing the plain text scan report
	 * @param config     AI configuration
	 * @return AI analysis text
	 * @throws DeepVioletException on AI errors
	 */
	String getAiAnalysis(InputStream scanReport, AiConfig config) throws DeepVioletException;

}