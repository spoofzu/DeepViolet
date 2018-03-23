package com.mps.deepviolet.suite.json;

public class CipherSuite {

	private String name;
	private String keyExchange;
	private String authentication;
	private String algorithm;
	private String integrity;

	// f.i ECDHE-ECDSA-AES256-GCM-SHA384
	public CipherSuite(String ciphersuitename) {
		name = ciphersuitename;
		parseConfig(name);
	}

	private void parseConfig(String suite) {
		String[] configs = suite.split("-");
		keyExchange = configs[0];
		authentication = configs[1];
		algorithm = configs[2] + configs[3];
		integrity = configs[4];
	}

	public String getName() {
		return name;
	}

	public String getKeyExchange() {
		return keyExchange;
	}

	public String getAuthentication() {
		return authentication;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public String getIntegrity() {
		return integrity;
	}

}
