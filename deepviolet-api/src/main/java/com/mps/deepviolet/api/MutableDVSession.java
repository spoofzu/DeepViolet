package com.mps.deepviolet.api;

import java.net.URL;
import java.rmi.dgc.VMID;
import java.util.HashMap;

class MutableDVSession implements IDVSession {

	private VMID id;
	private IDVHost[] hosts;
	private URL url;
	private HashMap<String,String> map = new HashMap<String,String>();
	
	MutableDVSession( URL url, IDVHost[] hosts ) {
		
		this.hosts = hosts;
		this.url = url;
		id = new VMID();
	}
	
	public IDVHost[] getHostInterfaces() {

		return hosts;
	}
	
	public String getPropertyValue( String keyname ) {
		return map.get(keyname);
	}
	
	public String[] getPropertyNames() {
		return map.keySet().toArray(new String[0]);
	}
	
	void setProperty( String key, String value ) {
		map.put(key,value);
	}

	public String getIdentity() {
		return id.toString();
	}

	public URL getURL() {
		return url;
	}

	
}
