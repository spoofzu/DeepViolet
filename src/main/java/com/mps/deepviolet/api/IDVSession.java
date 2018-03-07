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
		ENABLED_PROTOCOLS
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
	String getPropertyValue(SESSION_PROPERTIES keyname);
	
	/**
	 * Return property names.  Specify these in {@link #getPropertyValue(String)}
	 * to return the property value.
	 * @return Array of a property names
	 */
	SESSION_PROPERTIES[] getPropertyNames();
	
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
