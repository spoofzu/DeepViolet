package com.mps.deepviolet.persist;

import com.mps.deepviolet.api.ICipherSuite;

/**
 * Immutable implementation of {@link ICipherSuite} for deserialized scan data.
 *
 * @author Milton Smith
 */
public class ImmutableCipherSuite implements ICipherSuite {

	private final String name;
	private final String strength;
	private final String protocol;

	/**
	 * Creates an immutable cipher suite from deserialized fields.
	 *
	 * @param name     the IANA cipher suite name
	 * @param strength the strength evaluation
	 * @param protocol the handshake protocol version
	 */
	public ImmutableCipherSuite(String name, String strength, String protocol) {
		this.name = name;
		this.strength = strength;
		this.protocol = protocol;
	}

	@Override public String getSuiteName() { return name; }
	@Override public String getStrengthEvaluation() { return strength; }
	@Override public String getHandshakeProtocol() { return protocol; }
}
