package com.mps.deepviolet.api;

import java.net.URL;
import java.rmi.dgc.VMID;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

class MutableDVSession implements IDVSession {
	private VMID id;
	private List<IDVHost> hosts;
	private URL url;
	private Map<String,String> map = new HashMap<String,String>();
	
	MutableDVSession( URL url, List<IDVHost> hosts ) {
		this.hosts = hosts;
		this.url = url;
		id = new VMID();
	}
	
	public List<IDVHost> getHostInterfaces() {
		return hosts;
	}
	
	public String getPropertyValue( String keyname ) {
		return map.get(keyname);
	}
	
	public Set<String> getPropertyNames() {
		return map.keySet();
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
