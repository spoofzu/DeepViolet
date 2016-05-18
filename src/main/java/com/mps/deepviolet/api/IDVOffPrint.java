package com.mps.deepviolet.api;

/**
 * Offline print engine instance.  Useful for reporting
 * featurees that don't require initializing an online host.
 * For example, printing PEM encoded X.509 certificates.
 * @author Milton Smith
 */
public interface IDVOffPrint {

	/**
	 * Read X.509 PEM encoded certficiate from file and print to console device (UI/or System.out).
	 * @param file Fully qualified file to save
	 */
	public void printCertificate( String file );
	
}
