package com.mps.deepviolet.api;

import java.net.URL;

/**
 * Implementation of IDVhost
 * @author Milton Smith
 *
 */
class ImmutableDVHost implements IDVHost {

	private String hostname;
	private String ipaddress;
	private String cannonicalname;
	private URL url;
	
	/* (non-Javadoc)
	 */
	ImmutableDVHost( String hostname, String ipaddress, String cannonicalname, URL url ) {
		this.hostname = hostname;
		this.ipaddress = ipaddress;
		this.cannonicalname = cannonicalname;
		this.url = url;
	}
	/* (non-Javadoc)
	 */
	public String getHostName() {
		return hostname;
	}
	/* (non-Javadoc)
	 */
	public String getHostIPAddress() {
		return ipaddress;
	}
	/* (non-Javadoc)
	 */
	public String getHostCannonicalName() {
		return cannonicalname;
	}
	/* (non-Javadoc)
	 */
	public URL getURL() {
		return url;
	}

	
}
