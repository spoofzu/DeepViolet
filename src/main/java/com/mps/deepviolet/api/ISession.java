package com.mps.deepviolet.api;

import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Created upon successful initialization of a target host.
 * @author Milton Smith
 * @see <a href="DeepVioletFactory.html#initializeSession(URL)">DeepVioletFactory.initializeSession(URL)</a>
 */
public interface ISession {
	
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
		/** Socket keep-alive enabled. */
		SO_KEEPALIVE,
		/** Socket receive buffer size. */
		SO_RCVBUF,
		/** Socket linger-on-close timeout. */
		SO_LINGER,
		/** Socket read timeout. */
		SO_TIMEOUT,
		/** Socket address reuse enabled. */
		SO_REUSEADDR,
		/** Socket send buffer size. */
		SO_SENDBUFF,
		/** Client authentication required. */
		CLIENT_AUTH_REQ,
		/** Client authentication wanted. */
		CLIENT_AUTH_WANT,
		/** IP traffic class. */
		TRAFFIC_CLASS,
		/** TCP no-delay (Nagle disabled). */
		TCP_NODELAY,
		/** Enabled TLS/SSL protocols. */
		ENABLED_PROTOCOLS,
		/** DEFLATE compression support. */
		DEFLATE_COMPRESSION,
		/** Negotiated TLS protocol version. */
		NEGOTIATED_PROTOCOL,
		/** Negotiated cipher suite name. */
		NEGOTIATED_CIPHER_SUITE
	}
	
	/**
	 * Enumeration of supported cipher suite naming conventions.  The following conventions are 
	 * supported: CIPHER_NAME_CONVENTION.GnuTLS, CIPHER_NAME_CONVENTION.NSS,
	 * CIPHER_NAME_CONVENTION.IANA, CIPHER_NAME_CONVENTION.OpenSSL
	 */
	enum CIPHER_NAME_CONVENTION {
		/** GnuTLS naming convention. */
		GnuTLS,
		/** NSS naming convention. */
		NSS,
		/** IANA naming convention. */
		IANA,
		/** OpenSSL naming convention. */
		OpenSSL
	}

	/**
	 * All host interfaces
	 * @return Host interfaces
	 */
	IHost[] getHostInterfaces();

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
	 * Return a globally unique identity for this object
	 * @return ID
	 */
	String getIdentity();
	
	/**
	 * URL used to initial ISession in DeepVioletFactory
	 * @return Host url
	 * @see <a href="DeepVioletFactory.html#initializeSession(URL)">DeepVioletFactory.initializeSession(URL)</a>
	 */
	URL getURL();
	
	/**
	 * Get HTTP(S) response headers when session was initialized.
	 * @return Headers
	 */
	Map<String, List<String>> getHttpResponseHeaders();

	/**
	 * Get the OCSP stapled response bytes captured during TLS handshake.
	 * @return The stapled OCSP response bytes, or null if not present
	 */
	byte[] getStapledOcspResponse();

}
