package com.mps.deepviolet.suite.json;

import java.util.Map;

public class MozillaCerts {

	private String href;
	private Map<String, Configuration> configurations;
	private String version;

	public String getHref() {
		return href;
	}

	public void setHref(String href) {
		this.href = href;
	}

	public Map<String, Configuration> getConfigurations() {
		return configurations;
	}

	public void setConfigurations(Map<String, Configuration> configurations) {
		this.configurations = configurations;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

}
