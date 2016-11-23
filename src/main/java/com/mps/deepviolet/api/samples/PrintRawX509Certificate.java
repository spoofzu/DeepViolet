package com.mps.deepviolet.api.samples;

import java.net.URL;

import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVEng;
import com.mps.deepviolet.api.IDVSession;
import com.mps.deepviolet.api.IDVX509Certificate;

public class PrintRawX509Certificate {

	public PrintRawX509Certificate() throws Exception {

		URL url = new URL("https://github.com/");
		IDVSession session = DVFactory.initializeSession(url);
		IDVEng eng = DVFactory.getDVEng(session);
		IDVX509Certificate cert = eng.getCertificate();

		// Print out the certificate or whatever you want
		System.out.println("Raw X509 certificate");
		System.out.println(cert.toString());
	}

	public static final void main(String[] args) {
		try {
			new PrintRawX509Certificate();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

}
