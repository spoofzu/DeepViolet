package com.mps.deepviolet.api;

import java.net.URL;
import java.rmi.dgc.VMID;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mps.deepviolet.suite.CipherSuiteUtil;

class MutableDVSession implements IDVSession {

	private VMID id;
	private IDVHost[] hosts;
	private URL url;
	private HashMap<SESSION_PROPERTIES,String> map = new HashMap<SESSION_PROPERTIES,String>();
	private Map<String, List<String>> headers = new HashMap<String, List<String>>();
	
	MutableDVSession( URL url, IDVHost[] hosts ) {
		
		this.hosts = hosts;
		this.url = url;
		id = new VMID();
		
		try {
			headers = CipherSuiteUtil.getHttpResponseHeaders(url);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public IDVHost[] getHostInterfaces() {

		return hosts;
	}
	
	public String getPropertyValue( SESSION_PROPERTIES keyname ) {
		return map.get(keyname);
	}
	
	public SESSION_PROPERTIES[] getPropertyNames() {
		return map.keySet().toArray(new SESSION_PROPERTIES[0]);
	}
	
	void setProperty( SESSION_PROPERTIES soKeepalive, String value ) {
		map.put(soKeepalive,value);
	}

	public String getIdentity() {
		return id.toString();
	}

	public URL getURL() {
		return url;
	}

	public Map<String, List<String>> getHttpResponseHeaders() {	
		return headers;
	}

	
}
