package com.mps.deepviolet.api.samples;

import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVOnEng;
import com.mps.deepviolet.api.IDVSession;
import com.mps.deepviolet.api.IDVX509Certificate;
import com.mps.deepviolet.util.FileUtils;

public class PrintRawX509Certificate {
	
	public PrintRawX509Certificate() throws Exception {
		
		URL url = new URL("https://github.com/");
		IDVSession session = DVFactory.initializeSession(url);
		IDVOnEng eng = DVFactory.getDVEng(session);
		
		IDVX509Certificate cert = eng.getCertificate();
		// Do whatever you wish with the certifidate.
		
		System.out.println("Raw X509 certificate");
		System.out.println(cert.toString());
	}
	
	public static final void main(String[] args) {
		try {
			new PrintRawX509Certificate();
		}catch(Throwable t){
			t.printStackTrace();
		}
	}
	
}
