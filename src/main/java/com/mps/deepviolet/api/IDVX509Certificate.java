package com.mps.deepviolet.api;

import java.math.BigInteger;

/**
 * DeepViolet X.509 certificate represenation. Most values come from an
 * java.security.cert.X509Certificate instance upon initialization. However,
 * some values are computed for convience like CERT_FINGERPRINT which represents
 * the certificate fingerprint computed with the signing alorithm.
 * 
 * @author Milton Smith
 */
public interface IDVX509Certificate {

	// TODO: Properties guarenteed to be present

	String UNSUPPORTED_OID = "<UNSUPPORTED>";

	enum TrustState {
		TRUSTED, UNKNOWN, UNTRUSTED
	}

	enum ValidState {
		EXPIRED, VALID, NOT_YET_VALID
	}

	/**
	 * Certificate signing algorithm
	 * 
	 * @return Signing algorithm
	 */
	String getSigningAlgorithm();

	/**
	 * OID of certificate signing algorithm
	 * 
	 * @return OID in String form
	 */
	String getSigningAlgorithmOID();

	/**
	 * Certificate serial number
	 * 
	 * @return Certificate serial number
	 */
	BigInteger getCertificateSerialNumber();

	/**
	 * Certificate version number
	 * 
	 * @return Certificate version number
	 */
	int getCertificateVersion();

	/**
	 * Certificate not valid before timestamp
	 * 
	 * @return Timestamp certificate not valid before.
	 */
	String getNotValidBefore();

	/**
	 * Certificate not valid after timestamp
	 * 
	 * @return Timestamp certificate not valid after.
	 */
	String getNotValidAfter();

	/**
	 * Certificate validity state.
	 * 
	 * @return Validity state. Supported states, {@link ValidState#EXPIRED},
	 *         certificate is expired. The certificate was once valid but no
	 *         longer valid. {@link ValidState#NOT_YET_VALID}, the certificate
	 *         is not ready for use. {@link ValidState#VALID}, certifidate ready
	 *         for deployment and operations.
	 */
	ValidState getValidityState();

	/**
	 * Certificate Distinguished Name. Includes information that uniquely
	 * identifies the subject. Usually the subject is the host but could be
	 * other things in the future like code signer, etc.
	 * 
	 * @return DN of the subject.
	 */
	String getSubjectDN();

	/**
	 * Distinguished Name of the issuer. Includes information that uniquely
	 * identifies the issuing authority a Certificate Authority.
	 * 
	 * @return DN of the issuer.
	 */
	String getIssuerDN();

	/**
	 * Digital fingerprint of the certificate using the target algorithm
	 * identified by the certificate. For example, an MD5, SHA-1, SHA-256 hash.
	 * 
	 * @return String representation of an octet sequence.
	 */
	String getCertificateFingerPrint();

	/**
	 * Trust state of the certificte.
	 * 
	 * @return Supported states, {@link TrustState#UNTRUSTED}, certificate is
	 *         not be trusted. {@link TrustState#UNKNOWN}, the trust state of
	 *         the certificate cannot be determined. For example, if a
	 *         certificate is being examined and the owning host cannot be
	 *         determined or contacted. {@link TrustState#TRUSTED}, certificate
	 *         has past trust certification process.
	 */
	TrustState getTrustState();

	/**
	 * The signing authority is also the subject.
	 * 
	 * @return true, if the subjectDN of the certificate equals the issuerDN.
	 */
	boolean isSelfSignedCertificate();

	/**
	 * The certificate traces back to active Java trust store. Usually, the
	 * default trust store and root Certificate Authorities that ship with Java.
	 * Note: roots change between different versions of Java. Oracle removes,
	 * adds, and updates roots regularly.
	 * 
	 * @return true, the current certificate is a root in the active trust
	 *         store. false, the current certificate is not a root in the active
	 *         trust store.
	 */
	boolean isJavaRootCertificate();

	/**
	 * Non-critical OIDs.
	 * 
	 * @return Property names of non-critical OIDs.
	 */
	String[] getNonCritOIDProperties();

	/**
	 * Non-critical OID values
	 * 
	 * @param key
	 *            Key name of key/value pair.
	 * @return Property values for non-critical OIDs
	 */
	String getNonCritPropertyValue(String key);

	/**
	 * Test for the presence of non-critical OID key names
	 * 
	 * @param key
	 *            Key name of key/value pair.
	 * @return true, key exists. false, key does not exist.
	 */
	boolean isContainsNonCritPropertyKey(String key);

	/**
	 * Critical OIDs.
	 * 
	 * @return Property names of non-critical OIDs.
	 */
	String[] getCritOIDProperties();

	/**
	 * Critical OID values
	 * 
	 * @param key
	 *            Key name of key/value pair.
	 * @return Property values for non-critical OIDs
	 */
	String getCritPropertyValue(String key);

	/**
	 * Test for the presence of Critical OID key names
	 * 
	 * @param key
	 *            Key name of key/value pair.
	 * @return true, key exists. false, key does not exist.
	 */
	boolean isContainsCritPropertyKey(String key);

	/**
	 * Certificate chain of trust for the current certificate.
	 * 
	 * @return Array of certificates chaining back to a root. Note: the
	 *         certificates and root may or may not be trusted.
	 * @throws DVException
	 *             Thrown on problems.
	 */
	IDVX509Certificate[] getCertificateChain() throws DVException;

	/**
	 * Representation of a certificate provided as key/value pairs. Order of the
	 * results are not guaranteed.
	 * 
	 * @return Enumerated key/value pairs representing this certificate
	 *         instance.
	 */
	String toString();

	/**
	 * Test for equality. Two objects are considered equal if, 1) {@code obj} is
	 * an instance of {@code IDVX509Certificate}, 2) all key/value pairs are
	 * equal, 3) the length of
	 * {@code obj.getPropertyNames().length()==this.getPropertyNames().length()}
	 * 
	 * @return true, {@code obj} and {@code this} are equal. false, {@code obj}
	 *         and {@code this} are not equal
	 * @param obj
	 *            Object to compare
	 */
	boolean equals(Object obj);

}
