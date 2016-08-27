package com.mps.deepviolet.api;


class MutableDVCipherSuite implements IDVCipherSuite {
	private String name;
	private String eval;
	private String protocol;
	
	MutableDVCipherSuite( String name, String eval, String protocol ) {
		this.name = name;
		this.eval = eval;
		this.protocol = protocol;
	}
	
	public String getIANAName() {
		return name;
	}
	
	public String getStrengthEvaluation() {
		return eval;
	}
	
	public String getHandshakeProtocol() {
		return protocol;
	}
	
}
