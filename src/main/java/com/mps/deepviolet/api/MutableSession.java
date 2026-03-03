package com.mps.deepviolet.api;

import java.net.URL;
import java.rmi.dgc.VMID;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mutable implementation of {@link ISession}. Holds session state including
 * host interfaces, connection properties, HTTP response headers, and TLS metadata
 * (OCSP stapled responses, SCTs, fingerprint) gathered during session initialization.
 */
class MutableSession implements ISession {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.MutableSession");

	private VMID id;
	private IHost[] hosts;
	private URL url;
	private HashMap<SESSION_PROPERTIES,String> session_property_map = new HashMap<SESSION_PROPERTIES,String>();
	private Map<String, List<String>> headers = new HashMap<String, List<String>>();
	private byte[] stapledOcspResponse;
	private List<byte[]> scts = new ArrayList<>();
	private String tlsFingerprint;
	
	MutableSession( URL url, IHost[] hosts ) {
		
		this.hosts = hosts;
		this.url = url;
		id = new VMID();
		
		try {
			headers = CipherSuiteUtil.getHttpResponseHeaders(url);
		} catch (Exception e) {
			logger.error("Failed to fetch HTTP response headers", e);
		}
	}
	
	public String getIdentity() {
		return id.toString();
	}

	public URL getURL() {
		return url;
	}
	
	public IHost[] getHostInterfaces() {

		return hosts;
	}
	
	public Map<String, List<String>> getHttpResponseHeaders() {	
		return headers;
	}
	
	public String getSessionPropertyValue( SESSION_PROPERTIES keyname ) {
		return session_property_map.get(keyname);
	}
	
//	public SESSION_PROPERTIES[] getSessionPropertyNames() {
//		return session_property_map.keySet().toArray(new SESSION_PROPERTIES[0]);
//	}
	
	void setSessionPropertyValue( SESSION_PROPERTIES name, String value ) {
		session_property_map.put(name,value);
	}

	public byte[] getStapledOcspResponse() {
		return stapledOcspResponse;
	}

	void setStapledOcspResponse(byte[] response) {
		this.stapledOcspResponse = response;
	}

	public List<byte[]> getSCTs() {
		List<byte[]> result = new ArrayList<>();
		for (byte[] sct : scts) {
			result.add(sct.clone());
		}
		return result;
	}

	void addSCT(byte[] sct) {
		if (sct != null) {
			this.scts.add(sct.clone());
		}
	}

	void setSCTs(List<byte[]> scts) {
		this.scts.clear();
		if (scts != null) {
			for (byte[] sct : scts) {
				if (sct != null) {
					this.scts.add(sct.clone());
				}
			}
		}
	}

	/**
	 * Get the TLS server fingerprint for this session.
	 * @return 62-character TLS fingerprint, or null if not computed
	 */
	public String getTlsFingerprint() {
		return tlsFingerprint;
	}

	void setTlsFingerprint(String fingerprint) {
		this.tlsFingerprint = fingerprint;
	}

}
