package com.mps.deepviolet.api;

import java.security.cert.X509Certificate;

class DVX509OffCertificate extends DVX509Certificate {

	DVX509OffCertificate(IDVOnEng eng, X509Certificate cert) throws DVException {
		super(eng,cert);
	}

	void onlineInitializationOnly() throws DVException{
		//overridden in offline mode.  Don't exec in superclass.
	}
	
	//todo in the future may possible to override super.assignTrustState()
	// with online call to check trust of offline certificate.  For now,
	// any offline cert reports, Trusted State=>>>UNKNOWN<<<
	
}
