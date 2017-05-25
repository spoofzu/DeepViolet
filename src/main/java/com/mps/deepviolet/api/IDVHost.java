package com.mps.deepviolet.api;

import java.net.URL;

/**
 * Representation of host (e.g., TLS/SSL server) to DeepViolet
 * @author Milton Smith
 *
 */
public interface IDVHost {

	/**
	 * Retrieve name of host
	 * @return Host name
	 */
	String getHostName();
	
	/**
	 * Retrieve address of a host (e.g., IPv4 or IPv6)
	 * @return IP address
	 */
	String getHostIPAddress();
	
	/**
	 * Retrieve cannonical host name
	 * @return Cannonical host name
	 */
	String getHostCannonicalName();
	
	/**
	 * URL used to initial IDVSession in DVFactory
	 * @return Host url
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 */
	URL getURL();

	
}
