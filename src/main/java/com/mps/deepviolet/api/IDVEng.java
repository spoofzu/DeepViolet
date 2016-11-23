package com.mps.deepviolet.api;


/**
 * Interface specification for engine features available
 * from an initialized host.
 * @author Milton Smith
 *
 */
public interface IDVEng {

	/**
	 * Return ciphersuites for the target host.
	 * @return Ciphersuites supported by target host.
	 * @throws DVException thrown on problems fetching ciphersuites.
	 */
	IDVCipherSuite[] getCipherSuites() throws DVException;

	/**
	 * Return session instance for the target host when IDVOnEng.
	 * was created.
	 * @return Session instance for target host.
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 */
	IDVSession getDVSession();
	
//	/**
//     * Return online print engine instance for target.
//     * host when IDVOnEng was created.
//	 * @return Online print engine.
//	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
//	 * @throws DVException Thrown on problems
//	 */
//	IDVPrint getDVPrint() throws DVException;
//	
//	/**
//     * Return online print engine instance for target
//     * host when IDVOnEng was created.
//     * @param con Buffer to write reports.
//	 * @return Online print engine.
//	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
//	 * @throws DVException Thrown on problems
//	 */
//	IDVPrint getDVPrint(StringBuffer con) throws DVException;

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
	
//	/**
//     * Return offline print engine instance.  Useful for reporting
//     * featurees that don't require initializing an online host.
//     * For example, printing PEM encoded X.509 certificates.
//	 * @return Offline print engine instance
//	 * @throws DVException on problems.
//	 */
//	IDVOffPrint getDVOffPrint() throws DVException;
	
	
}