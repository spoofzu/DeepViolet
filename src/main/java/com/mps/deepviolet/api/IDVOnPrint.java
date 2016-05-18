package com.mps.deepviolet.api;


/**
 * Online print engine instance.  Useful for reporting
 * featurees that require initializing an online host.
 * @author Milton Smith
 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
 */
public interface IDVOnPrint {

	/**
	 * Print start of scan report.
	 */
	public void printReportHeader();

	/**
	 * Print a list of HTTPS response heads for the given URL
	 */
	public void printHostHttpResponseHeaders();

	/**
	 * Print various information about host system under assessment.
	 */
	public void printHostInformation();

	/**
	 * Print section for the supported ciphersuites.
	 */
	public void printSupportedCipherSuites();

	/**
	 * Print section for the connection characteristics.
	 */
	public void printConnectionCharacteristics();

	/**
	 * Print security for the server certificate. 
	 */
	public void printServerCertificate();

	/**
	 * Print security for the server certificate chain.
	 */
	public void printServerCertificateChain();
	
	/**
	 * OS dependent End of Line character.
	 * @return EOL
	 */
	public String getEOL();
	
	/**
	 * Print a single line to the console buffer.
	 * @param text Text to print.
	 */
	public void println( String text );
}