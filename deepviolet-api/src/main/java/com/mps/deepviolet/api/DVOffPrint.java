package com.mps.deepviolet.api;

/**
 * Report utility that controls how each report section is printed.
 * This class is used for offline printing (without a host).  There
 * are very 
 * @author Milton Smith
 */
public class DVOffPrint extends DVPrint {

	DVOffPrint(IDVOnEng eng, StringBuffer con) throws DVException {
		super.eng = eng;
		this.oeng = DVFactory.getDVOffEng();
		this.session = eng.getDVSession();
		this.con = con;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printReportHeader()
	 */
	public final void printReportHeader( ) {}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printHostHttpResponseHeaders()
	 */
	public void printHostHttpResponseHeaders( ) {}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printHostInformation()
	 */
	public void printHostInformation() {}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printSupportedCipherSuites()
	 */
	public void printSupportedCipherSuites() {}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printConnectionCharacteristics()
	 */
	public void printConnectionCharacteristics() {}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printServerCertificate()
	 */
	public void printServerCertificate() {}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#printServerCertificateChain()
	 */
	public void printServerCertificateChain() {}
	
	
}
