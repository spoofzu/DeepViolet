package com.mps.deepviolet.api;

import java.io.IOException;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.SSLHandshakeException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.suite.CipherSuiteUtil;

/**
 * Implementation of IDVX509Certificate specification
 * 
 * @author Milton Smith
 * @see com.mps.deepviolet.api.IDVX509Certificate
 */
class DVX509Certificate implements IDVX509Certificate {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolet.api.DVX509Certificate");
	private final String EOL = System.getProperty("line.separator");

	X509Certificate cert;
	X509Certificate[] chain;
	DVX509Certificate[] dvChain;
	IDVOnEng eng;

	String signingAlgorithm;
	String signingAlgorithmOID;
	BigInteger certificateSerialNumber;
	int iCertificateVersion;
	String notValidBefore;
	String notValidAfter;
	int iValidityState;
	String subjectDN;
	String issuerDN;
	int iTrustState;
	boolean bSelfSignedCertificate;
	boolean bJavaRootCertificate;
	String certificateFingerPrint;

	HashMap<String, String> non_crit_oid_map = new HashMap<String, String>();
	HashMap<String, String> crit_oid_map = new HashMap<String, String>();

	DVX509Certificate() {
	}

	/**
	 * CTOR
	 * 
	 * @param cert
	 *            X509Certificate to inialize
	 * @throws DVException
	 *             Thown on trouble
	 */
	DVX509Certificate(IDVOnEng eng, X509Certificate cert) throws DVException {

		try {

			this.cert = cert;
			this.eng = eng;

			signingAlgorithm = cert.getSigAlgName();
			notValidBefore = cert.getNotBefore().toString();
			notValidAfter = cert.getNotAfter().toString();
			certificateSerialNumber = cert.getSerialNumber();
			subjectDN = cert.getSubjectDN().toString();
			issuerDN = cert.getIssuerDN().toString();
			signingAlgorithmOID = cert.getSigAlgOID();
			iCertificateVersion = cert.getVersion();
			iTrustState = TRUST_STATE_UNKNOWN; // default

			// TODO: Signature algorithm is different than a digest algorithm.
			// Need to understand
			// if parsing SHA256withRSA into SHA256 will work consistently.
			byte[] encx509 = cert.getEncoded();
			String sa = signingAlgorithm.substring(0,
					signingAlgorithm.indexOf("with"));
			certificateFingerPrint = CipherSuiteUtil.signerFingerprint(encx509,
					sa);

			// Check certificate validity, start < now < expiration.
			try {
				try {
					cert.checkValidity();
					iValidityState = VALID_STATE_VALID;
				} catch (CertificateNotYetValidException e) {
					iValidityState = VALID_STATE_NOT_YET_VALID;
				}
			} catch (CertificateExpiredException c) {
				iValidityState = VALID_STATE_EXPIRED;
			}

			// Gather non-critical OIDs
			Set<String> oids = cert.getNonCriticalExtensionOIDs();
			if (oids == null) {
				// If no OIDs don't add anything to the map.
			} else {
				assignOIDs(non_crit_oid_map, oids);
			}

			// Gather critical OIDs
			oids = cert.getCriticalExtensionOIDs();
			if (oids == null) {
				// If no OIDs don't add anything to the map.
			} else {
				assignOIDs(crit_oid_map, oids);
			}

			// Self-signed or not.
			bSelfSignedCertificate = CipherSuiteUtil
					.isSelfSignedCertificate(cert);

			// At this point we have printed all certs returned by the server
			// (via getServerCertificateChain()). Note the server does NOT
			// return the root CA cert to us. However, we can infer the
			// root by checking IssuerDN of the last Intermediate CA and
			// the AuthorityKeyIdentifier (if present).
			bJavaRootCertificate = CipherSuiteUtil.isJavaRootCertificateDN(cert
					.getIssuerDN().getName());

			// Initialize online only activities. Easy to override in child.
			onlineInitializationOnly();

		} catch (Exception e) {
			new DVException(e);
		}

	}

	/**
	 * Convience method to allow initialization of some features we don't want
	 * to execute in offline version. Allows subclasses to easily override and
	 * block execution of these features.
	 * 
	 * @throws DVException
	 *             Thrown on problems.
	 */
	void onlineInitializationOnly() throws DVException {

		// Assign cert chain
		assignCertificateChain();

		// Assign the trust state, trusted, untrusted, unknown to the cert
		assignTrustState();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getSigningAlgorithm()
	 */
	public String getSigningAlgorithm() {
		return signingAlgorithm;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.mps.deepviolet.api.IDVX509Certificate.getCertificateSerialNumber()
	 */
	public BigInteger getCertificateSerialNumber() {
		return certificateSerialNumber;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getSigningAlgorithmOID()
	 */
	public String getSigningAlgorithmOID() {
		return signingAlgorithmOID;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCertificateVersion()
	 */
	public int getCertificateVersion() {
		return iCertificateVersion;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNotValidBefore()
	 */
	public String getNotValidBefore() {
		return notValidBefore;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNotValidAfter()
	 */
	public String getNotValidAfter() {
		return notValidAfter;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getValidityState()
	 */
	public int getValidityState() {
		return iValidityState;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getSubjectDN()
	 */
	public String getSubjectDN() {
		return subjectDN;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getIssuerDN()
	 */
	public String getIssuerDN() {
		return issuerDN;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getTrustState()
	 */
	public int getTrustState() {
		return iTrustState;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.isSelfSignedCertificate()
	 */
	public boolean isSelfSignedCertificate() {
		return bSelfSignedCertificate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.isJavaRootCertificate()
	 */
	public boolean isJavaRootCertificate() {
		return bJavaRootCertificate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.mps.deepviolet.api.IDVX509Certificate.getCertificateFingerPrint()
	 */
	public String getCertificateFingerPrint() {
		return certificateFingerPrint;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNonCritOIDProperties()
	 */
	public String[] getNonCritOIDProperties() {
		Set<String> oids = non_crit_oid_map.keySet();
		return oids.toArray(new String[0]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.mps.deepviolet.api.IDVX509Certificate.getNonCritPropertyValue(String)
	 */
	public String getNonCritPropertyValue(String key) {
		if (key == null || !non_crit_oid_map.containsKey(key))
			return null;
		return non_crit_oid_map.get(key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCritPropertyValue()
	 */
	public String[] getCritOIDProperties() {
		Set<String> oids = crit_oid_map.keySet();
		return oids.toArray(new String[0]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.mps.deepviolet.api.IDVX509Certificate.getCritPropertyValue(String)
	 */
	public String getCritPropertyValue(String key) {
		if (key == null || !crit_oid_map.containsKey(key))
			return null;
		return crit_oid_map.get(key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.mps.deepviolet.api.IDVX509Certificate.isContainsNonCritPropertyKey()
	 */
	public boolean isContainsNonCritPropertyKey(String key) {
		return non_crit_oid_map.containsKey(key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.mps.deepviolet.api.IDVX509Certificate.isContainsCritPropertyKey()
	 */
	public boolean isContainsCritPropertyKey(String key) {
		return crit_oid_map.containsKey(key);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCertificateChain()
	 */
	public synchronized IDVX509Certificate[] getCertificateChain()
			throws DVException {

		if (dvChain != null)
			return dvChain;
		ArrayList<DVX509Certificate> list = new ArrayList<DVX509Certificate>();
		for (X509Certificate lcert : chain) {
			list.add(new DVX509Certificate(eng, lcert));
		}
		dvChain = list.toArray(new DVX509Certificate[0]);
		return dvChain;
	}

	/**
	 * Assign OIDs to the key/value store.
	 * 
	 * @param map
	 *            Map to insert OIDs
	 * @param OIDs
	 *            Set of OIDs to assign.
	 */
	void assignOIDs(HashMap<String, String> lmap, Set<String> OIDs) {

		Iterator<String> i2 = OIDs.iterator();
		while (i2.hasNext()) {

			String oid = (String) i2.next();
			// TODO unsupported oids should be found in logs and improved over
			// time.
			String value = UNSUPPORTED_OID;

			try {
				value = CipherSuiteUtil.getExtensionValue(cert, oid);
			} catch (IOException e) {
				logger.error("Can't print ASN.1 value", e);
			}
			lmap.put(CipherSuiteUtil.getOIDKeyName(oid), value);

		}

	}

	/**
	 * Assign the certificate chain to this certificate.
	 * 
	 * @throws DVException
	 *             Thrown on problems
	 */
	void assignCertificateChain() throws DVException {

		try {
			chain = CipherSuiteUtil.getServerCertificateChain(eng
					.getDVSession().getURL());

		} catch (SSLHandshakeException e) {

			if (e.getMessage().indexOf("PKIX") > 0) {
				String msg = "Certificate chain failed validation. err="
						+ e.getMessage();
				logger.error(msg, e);
				throw new DVException(msg, e);
			} else {
				String msg = "SSLHandshakeException. err=" + e.getMessage();
				logger.error(msg, e);
				throw new DVException(msg, e);
			}

		} catch (Exception e) {
			String msg = "Problem fetching certificates. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DVException(msg, e);
		}

	}

	/**
	 * The utility of this method is that we don't have the URL of the server
	 * that this certificate came from. Scenario is we read from file. To check
	 * trust we need a connection to the server. Here we try to create a host
	 * based upon some assumptions. If we could check trust without the signing
	 * algorithm in checkTrustedCertificate( X509Certificate[] certs, URL url)
	 * then all this URL finding could be elimated. Need to look into this more.
	 * All this is only a best effort to establish the trust relationship while
	 * offline (e.g., --serverurl not specified).
	 * 
	 * @param lcert
	 *            X.509 certificate to determine trust state.
	 */
	void assignTrustState() throws DVException {

		try {

			// todo should look at a differnt way to do this later

			boolean bTrusted = CipherSuiteUtil.checkTrustedCertificate(chain,
					eng.getDVSession().getURL());
			if (bTrusted) {
				iTrustState = TRUST_STATE_TRUSTED;
			} else {
				iTrustState = TRUST_STATE_UNTRUSTED;
			}

		} catch (KeyStoreException e) {
			iTrustState = TRUST_STATE_UNKNOWN;
			throw new DVException("Problem accessing keystore, err="
					+ e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {
			iTrustState = TRUST_STATE_UNKNOWN;
			throw new DVException("No ciphersuite available, err="
					+ e.getMessage(), e);
		} catch (UnknownHostException e) {
			iTrustState = TRUST_STATE_UNKNOWN;
			throw new DVException("Unknown host, err=" + e.getMessage(), e);
		} catch (IOException e) {
			throw new DVException("File system problem, err=" + e.getMessage(),
					e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.toString()
	 */
	public String toString() {

		StringBuffer buff = new StringBuffer(2500);

		buff.append(super.toString());
		buff.append(EOL);

		buff.append("SUBJECTDN");
		buff.append('=');
		buff.append(subjectDN);
		buff.append(EOL);

		buff.append("SIGNING_ALGORITHM");
		buff.append('=');
		buff.append(signingAlgorithm);
		buff.append(EOL);

		buff.append("CERTIFICATE_FINGERPRINT");
		buff.append('=');
		buff.append(certificateFingerPrint);
		buff.append(EOL);

		buff.append("ISSUERDN");
		buff.append('=');
		buff.append(issuerDN);
		buff.append(EOL);

		buff.append("VALIDITY_STATE");
		buff.append('=');
		String state = "<ERROR>";
		if (iValidityState == VALID_STATE_EXPIRED) {
			state = "EXPIRED";
		} else if (iValidityState == VALID_STATE_VALID) {
			state = "VALID";
		} else if (iValidityState == VALID_STATE_NOT_YET_VALID) {
			state = "NOT_YET_VALID";
		}
		buff.append(state);
		buff.append(EOL);

		buff.append("TRUST_STATE");
		buff.append('=');
		state = "<ERROR>";
		if (iTrustState == TRUST_STATE_TRUSTED) {
			state = "TRUSTED";
		} else if (iTrustState == TRUST_STATE_UNKNOWN) {
			state = "UNKNOWN";
		} else if (iTrustState == TRUST_STATE_UNTRUSTED) {
			state = "UNTRUSTED";
		}
		buff.append(state);
		buff.append(EOL);

		buff.append("VALIDITY_NOT_VALID_BEFORE");
		buff.append('=');
		buff.append(notValidBefore);
		buff.append(EOL);

		buff.append("VALIDITY_NOT_VALID_AFTER");
		buff.append('=');
		buff.append(notValidAfter);
		buff.append(EOL);

		buff.append("CERTIFICATE_SERIAL_NUMBER");
		buff.append('=');
		buff.append(certificateSerialNumber);
		buff.append(EOL);

		buff.append("CERTIFICATE_VERSION");
		buff.append('=');
		buff.append(Integer.toString(iCertificateVersion));
		buff.append(EOL);

		buff.append("SELF_SIGNED_CERTIFICATE");
		buff.append('=');
		buff.append(Boolean.toString(bSelfSignedCertificate));
		buff.append(EOL);

		buff.append("JAVA_ROOT_CERTIFICATE");
		buff.append('=');
		buff.append(Boolean.toString(bJavaRootCertificate));
		buff.append(EOL);

		buff.append("SIGNING_ALGORITHM_OID");
		buff.append('=');
		buff.append(signingAlgorithmOID);
		buff.append(EOL);

		// Non-crit-OIDs
		buff.append("CRIT_OIDS[");
		Set<String> oids = crit_oid_map.keySet();
		Iterator<String> i = oids.iterator();
		boolean fi = true;
		while (i.hasNext()) {
			String key = i.next();
			String value = crit_oid_map.get(key);
			if (!fi)
				buff.append(", ");
			buff.append(key);
			buff.append('=');
			buff.append(value);
			fi = false;
		}
		buff.append("]");
		buff.append(EOL);

		// Non-crit-OIDs
		buff.append("NON_CRIT_OIDS[");
		oids = non_crit_oid_map.keySet();
		i = oids.iterator();
		fi = true;
		while (i.hasNext()) {
			String key = i.next();
			String value = non_crit_oid_map.get(key);
			if (!fi)
				buff.append(", ");
			buff.append(key);
			buff.append('=');
			buff.append(value);
			fi = false;
		}
		buff.append("]");
		buff.append(EOL);

		return buff.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVX509Certificate.equals(Object)
	 */
	public boolean equals(Object obj) {

		boolean o1 = false;
		boolean o2 = false;
		boolean o3 = false;
		boolean o4 = false;
		boolean o5 = false;
		boolean o6 = false;
		boolean o7 = false;
		boolean o8 = false;
		boolean o9 = false;
		boolean o10 = false;
		boolean o11 = false;
		boolean o12 = false;
		boolean o13 = false;
		boolean o14 = false;
		boolean o15 = false;

		if (obj != null) {
			if (obj instanceof IDVX509Certificate) {
				IDVX509Certificate c = (IDVX509Certificate) obj;

				o1 = signingAlgorithm.equals(c.getSigningAlgorithm());
				o2 = signingAlgorithmOID.equals(c.getSigningAlgorithmOID());
				o3 = iCertificateVersion == c.getCertificateVersion();
				o4 = notValidBefore.equals(c.getNotValidBefore());
				o5 = notValidAfter.equals(c.getNotValidAfter());
				o6 = iValidityState == c.getValidityState();
				o7 = subjectDN.equals(c.getSubjectDN());
				o8 = issuerDN.equals(c.getIssuerDN());
				o9 = iTrustState == c.getTrustState();
				o10 = bSelfSignedCertificate;
				o11 = bJavaRootCertificate;
				o12 = certificateFingerPrint.equals(c
						.getCertificateFingerPrint());

				o13 = true;
				Iterator<String> keys = non_crit_oid_map.keySet().iterator();
				while (keys.hasNext()) {
					String key = keys.next();
					if (c.isContainsNonCritPropertyKey(key)) {
						o13 = false;
						break;
					}
				}

				o14 = true;
				keys = crit_oid_map.keySet().iterator();
				while (keys.hasNext()) {
					String key = keys.next();
					if (c.isContainsCritPropertyKey(key)) {
						o14 = false;
						break;
					}
				}

				o15 = certificateSerialNumber == c.getCertificateSerialNumber();

			}
		}
		return (o1 && o2 && o3 && o4 && o5 && o6 && o7 && o8 && o9 && o10
				&& o11 && o12 && o13 && o14 && o15);
	}

}
