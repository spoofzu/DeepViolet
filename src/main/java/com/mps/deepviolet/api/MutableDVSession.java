package com.mps.deepviolet.api;

import java.net.URL;
import java.rmi.dgc.VMID;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class MutableDVSession implements IDVSession {

	private VMID id;
	private IDVHost[] hosts;
	private URL url;
	private HashMap<SESSION_PROPERTIES,String> session_property_map = new HashMap<SESSION_PROPERTIES,String>();
	private HashMap<VULNERABILITY_ASSESSMENTS,String> vulnerability_assessment_map = new HashMap<VULNERABILITY_ASSESSMENTS,String>();
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
	
	public String getIdentity() {
		return id.toString();
	}

	public URL getURL() {
		return url;
	}
	
	public IDVHost[] getHostInterfaces() {

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

	public String getVulnerabilityAssessmentValue(VULNERABILITY_ASSESSMENTS keyname) {
		return vulnerability_assessment_map.get(keyname);
	}
	
	void setVulnerabilityAssessmentValue( VULNERABILITY_ASSESSMENTS name, String value ) {
		vulnerability_assessment_map.put(name,value);
	}

//	public VULNERABILITY_ASSESSMENTS[] getVulnerabilityAssessmentValues() {
//		return vulnerability_assessment_map.keySet().toArray(new VULNERABILITY_ASSESSMENTS[0]);
//	}



	
}
