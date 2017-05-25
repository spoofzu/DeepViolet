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
	 * All host interfaces
	 * @return Host interfaces
	 */
	IDVHost[] getHostInterfaces();

	/**
	 * Return target property name
	 * @param keyname Name of target property to return
	 * @return Property value
	 */
	String getPropertyValue(String keyname);
	
	/**
	 * Return property names.  Specify these in {@link #getPropertyValue(String)}
	 * to return the property value.
	 * @return Array of a property names
	 */
	String[] getPropertyNames();
	
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
