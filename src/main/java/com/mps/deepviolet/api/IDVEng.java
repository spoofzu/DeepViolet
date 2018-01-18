package com.mps.deepviolet.api;


/**
 * Interface specification for engine features available
 * from an initialized host.
 * @author Milton Smith
 *
 */
public interface IDVEng {

	/**
	 * Enumeration of supported ciphersuite naming conventions.
	 */
	public enum CIPHER_NAME_CONVENTION {
		GnuTLS, NSS, IANA, OpenSSL
	}
	
	/**
	 * Return ciphersuites for the target host.  Calls <code>getCipherSuites(CIPHER_NAME_CONVENTION CIPHER_NAME_CONVENTION)</code> with
	 * CIPHER_NAME_CONVENTION.IANA as the default.
	 * @return Ciphersuites supported by target host.
	 * @throws DVException thrown on problems fetching ciphersuites.
	 */
	IDVCipherSuite[] getCipherSuites() throws DVException;	
	
	/**
	 * Return ciphersuites for the target host.
	 * @return Ciphersuites supported by target host.
	 * @throws DVException thrown on problems fetching ciphersuites.
	 */
	IDVCipherSuite[] getCipherSuites(CIPHER_NAME_CONVENTION CIPHER_NAME_CONVENTION) throws DVException;

	/**
	 * Return session instance for the target host when IDVOnEng.
	 * was created.
	 * @return Session instance for target host.
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 */
	IDVSession getDVSession();

	/**
	 * Write PEM encoded X.509 certificate for the target
	 * host when IDVOnEng was created to a fully qualified
	 * file name.
	 * @param file Fully qualified file name
	 * @return Returns the number of bytes written to disk
	 * @throws DVException Thrown on problems writing to the disk.
	 */
	long writeCertificate(String file) throws DVException;
	
	/**
	 * Retrieve a IDVX509Certificate.
	 * @return Return IDVX509Certificate representing host associated
	 * with IDVOnEng instance.
	 * @throws DVException Thrown on problems reading certificate.
	 */
	IDVX509Certificate getCertificate() throws DVException;
	
	/**
	 * Return the Major Version of DeepViolet.  Incremented upon significant
	 * addition of new features.  Existing features could also break code.
	 * Callers are urged to test upon implementing new major versions.
	 * @return Number indicating DeepVioloet Major Version.
	 */
	int getDeepVioletMajorVersion();

	/**
	 * Return the Minor Version of DeepViolet.  Incremented upon significant
	 * improvement to existing features.   Callers are urged to test upon
	 * implementing new major versions.
	 * @return Number indicating DeepVioloet Minor Version.
	 */
	int getDeepVioletMinorVersion();

	/**
	 * Return the Build Version of DeepViolet.  Incremented on bug fixes to
	 * existing features.  It's not anticipated this any improvements will
	 * break code.  Callers are urged to perform basic unit tests.
	 * @return Number indicating DeepVioloet Build Version.
	 */
	int getDeepVioletBuildVersion();

	/**
	 * Return the DeepViolet version string.  
	 * @return Suitable for printing in log files, displaying in About boxes, etc.
	 */
	String getDeepVioletStringVersion();
	
	
}