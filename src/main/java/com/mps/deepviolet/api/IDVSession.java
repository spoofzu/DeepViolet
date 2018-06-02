package com.mps.deepviolet.api;

import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Created upon successful initialization of a target host.
 * @author Milton Smith
 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
 */
public interface IDVSession {
	
	/**
	 * Session properties.
	 * SO_KEEPALIVE, See documentation provided by javax.net.ssl.SSLSocket
	 * SO_RCVBUF, See documentation provided by javax.net.ssl.SSLSocket
	 * SO_LINGER, See documentation provided by javax.net.ssl.SSLSocket
	 * SO_TIMEOUT, See documentation provided by javax.net.ssl.SSLSocket
	 * SO_REUSEADDR, See documentation provided by javax.net.ssl.SSLSocket
	 * SO_SENDBUFF, See documentation provided by javax.net.ssl.SSLSocket
	 * CLIENT_AUTH_REQ, See documentation provided by javax.net.ssl.SSLSocket
	 * CLIENT_AUTH_WANT, See documentation provided by javax.net.ssl.SSLSocket
	 * TRAFFIC_CLASS, See documentation provided by javax.net.ssl.SSLSocket
	 * TCP_NODELAY, See documentation provided by javax.net.ssl.SSLSocket
	 * ENABLED_PROTOCOLS, See documentation provided by javax.net.ssl.SSLSocket
	 */
	public enum SESSION_PROPERTIES {
		SO_KEEPALIVE,
		SO_RCVBUF,
		SO_LINGER,
		SO_TIMEOUT,
		SO_REUSEADDR,
		SO_SENDBUFF,
		CLIENT_AUTH_REQ,
		CLIENT_AUTH_WANT,
		TRAFFIC_CLASS,
		TCP_NODELAY,
		ENABLED_PROTOCOLS,
		DEFLATE_COMPRESSION
	}
	
	/**
	 * Vulnerability assessment properties.
	 * MINIMAL_ENCRYPTION_STRENGTH, Minimal encryption strength of supported ciphersuites
	 * ACHIEVABLE_ENCRYPTION_STRENGTH, Maximum achievable encryption strength of supported ciphersuites
	 * BEAST_VULNERABLE, true, vulnerable to BEAST attack.  false, not vulnerable to BEAST attack
	 * CRIME_VULNERABLE, true, vulnerable to CRIME attack.  false, not vulnerable to CRIME attack
	 * FREAK_VULNERABLE, true, vulnerable to FREAK attack.  false, not vulnerable to FREAK attack
	 */
	public enum VULNERABILITY_ASSESSMENTS {
		MINIMAL_ENCRYPTION_STRENGTH,
		ACHIEVABLE_ENCRYPTION_STRENGTH,
		BEAST_VULNERABLE,
		CRIME_VULNERABLE,
		FREAK_VULNERABLE
	}
	
	/**
	 * Enumeration of supported ciphersuite naming conventions.  The following conventions are 
	 * supported: CIPHER_NAME_CONVENTION.GnuTLS, CIPHER_NAME_CONVENTION.NSS,
	 * CIPHER_NAME_CONVENTION.IANA, CIPHER_NAME_CONVENTION.OpenSSL
	 */
	enum CIPHER_NAME_CONVENTION {
		GnuTLS, NSS, IANA, OpenSSL
	}

	/**
	 * All host interfaces
	 * @return Host interfaces
	 */
	IDVHost[] getHostInterfaces();

	/**
	 * Return target property value
	 * @param keyname Name of target property to return
	 * @return Property value
	 */
	String getSessionPropertyValue(SESSION_PROPERTIES keyname);
	
//	/**
//	 * Return property names.  Specify these in {@link #getSessionPropertyValue(String)}
//	 * to return the property value.
//	 * @return Array of a property names
//	 */
//	SESSION_PROPERTIES[] getSessionPropertyNames();
	
	/**
	 * Return target vulnerability assessment value
	 * @param keyname Name of target property to return
	 * @return Property value
	 */
	String getVulnerabilityAssessmentValue(VULNERABILITY_ASSESSMENTS keyname);
	
//	/**
//	 * Return vulnerability names.  Specify these in {@link #getSessionPropertyValue(String)}
//	 * to return the property value.
//	 * @return Array of a property names
//	 */
//	VULNERABILITY_ASSESSMENTS[] getVulnerabilityAssessmentValues();
	
	/**
	 * Return a globally unique identity for this object
	 * @return ID
	 */
	String getIdentity();
	
	/**
	 * URL used to initial IDVSession in DVFactory
	 * @return Host url
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 */
	URL getURL();
	
	/**
	 * Get HTTP(S) response headers when session was initialized.
	 * @return Headers
	 */
	Map<String, List<String>> getHttpResponseHeaders();

}
