package com.mps.deepviolet.api;


/**
 * Mutable data holder for a single cipher suite, storing its name,
 * strength evaluation, and the TLS/SSL protocol version it was negotiated under.
 */
class MutableCipherSuite implements ICipherSuite {

	private String name;
	private String eval;
	private String protocol;
	
	MutableCipherSuite( String name, String eval, String protocol ) {
		this.name = name;
		this.eval = eval;
		this.protocol = protocol;
	}
	
	public String getSuiteName() {
		return name;
	}
	
	public String getStrengthEvaluation() {
		return eval;
	}
	
	public String getHandshakeProtocol() {
		return protocol;
	}
	
}
