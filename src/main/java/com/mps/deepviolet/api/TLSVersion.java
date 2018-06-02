package com.mps.deepviolet.api;

import com.fasterxml.jackson.annotation.JsonValue;

enum TLSVersion {

	TLSVersion1("TLSv1"), TLSVersion1_1("TLSv1.1"), TLSVersion1_2("TLSv1.2"), SSLVersion3("SSLv3");

	private String version;

	private TLSVersion(String version) {
		this.version = version;
	}

	@JsonValue
	public String getVersion() {
		return version;
	}
}
