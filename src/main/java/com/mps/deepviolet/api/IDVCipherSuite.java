package com.mps.deepviolet.api;

/**
 * DeepViolet representation of a cipher suite
 * @author Milton Smith
 */
public interface IDVCipherSuite {

	/**
	 * Cipher suite name.
	 * @return Cipher name
	 */
	String getSuiteName();
	
	/**
	 * Evaluation of cipher suite strength
	 * @return Cipher suite valuation, STRONG, WEAK, etc.
	 */
	String getStrengthEvaluation();
	
	/**
	 * Handshake protocol this ciphersuite belongs
	 * @return Handshake protocol, TLSv1, TLSv1.2, etc.
	 */
	String getHandshakeProtocol();
	
}
