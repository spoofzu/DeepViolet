package com.mps.deepviolet.suite;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Classifications {
	public String getNSS() {
		return NSS;
	}

	public void setNSS(String nSS) {
		NSS = nSS;
	}

	public String getIANA() {
		return IANA;
	}

	public void setIANA(String iANA) {
		IANA = iANA;
	}

	@JsonProperty("GnuTLS")
	private String GnuTLS;
	@JsonIgnore

	@JsonProperty("NSS")
	private String NSS;

	@JsonProperty("IANA")
	private String IANA;

	@JsonProperty("OpenSSL")
	private String OpenSSL;

	public String getGnuTLS() {
		return GnuTLS;
	}

	public void setGnuTLS(String gnuTLS) {
		GnuTLS = gnuTLS;
	}

}
