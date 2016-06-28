package com.mps.deepviolet.api;


/**
 * Interface specification for engine features available
 * from an initialized host.
 * @author Milton Smith
 *
 */
public interface IDVOnEng {

	/**
	 * Return ciphersuites for the target host.
	 * @return Ciphersuites supported by target host.
	 * @throws DVException thrown on problems fetching ciphersuites.
	 */
	public IDVCipherSuite[] getCipherSuites() throws DVException;

	/**
	 * Return session instance for the target host when IDVOnEng.
	 * was created.
	 * @return Session instance for target host.
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 */
	public IDVSession getDVSession();
	
	/**
     * Return online print engine instance for target.
     * host when IDVOnEng was created.
	 * @return Online print engine.
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 * @throws DVException Thrown on problems
	 */
	public IDVOnPrint getDVOnPrint() throws DVException;
	
	/**
     * Return online print engine instance for target
     * host when IDVOnEng was created.
     * @param con Buffer to write reports.
	 * @return Online print engine.
	 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
	 * @throws DVException Thrown on problems
	 */
	public IDVOnPrint getDVOnPrint( StringBuffer con) throws DVException;

	/**
	 * Write PEM encoded X.509 certificate for the target
	 * host when IDVOnEng was created to a fully qualified
	 * file name.
	 * @param file Fully qualified file name
	 * @return Returns the number of bytes written to disk
	 * @throws DVException Thrown on problems writing to the disk.
	 */
	public long writeCertificate(String file) throws DVException;
	
	/**
	 * Retrieve a IDVX509Certificate.
	 * @return Return IDVX509Certificate reprsenting host associated
	 * with IDVOnEng instance.
	 * @throws DVException Thrown on problems reading certificate.
	 */
	public IDVX509Certificate getCertificate() throws DVException;
	
	//todo xxxx
	//public Iterator<IDVX509Certificate> getCertificateChain() throws DVException;
	
	
}