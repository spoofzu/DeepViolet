package com.mps.deepviolet.api;

import java.util.Map;

public class JsonLdrMozillaCerts {

	private String href;
	private Map<String, JsonLdrConfiguration> configurations;
	private String version;

	public String getHref() {
		return href;
	}

	public void setHref(String href) {
		this.href = href;
	}

	public Map<String, JsonLdrConfiguration> getConfigurations() {
		return configurations;
	}

	public void setConfigurations(Map<String, JsonLdrConfiguration> configurations) {
		this.configurations = configurations;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

}
