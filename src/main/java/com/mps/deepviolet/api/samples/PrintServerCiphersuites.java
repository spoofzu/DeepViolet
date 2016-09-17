package com.mps.deepviolet.api.samples;

import java.net.URL;
import java.util.HashMap;

import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVCipherSuite;
import com.mps.deepviolet.api.IDVOnEng;
import com.mps.deepviolet.api.IDVSession;

public class PrintServerCiphersuites {
	
	public PrintServerCiphersuites() throws Exception {
		
		URL url = new URL("https://github.com/");
		IDVSession session = DVFactory.initializeSession(url);
		IDVOnEng eng = DVFactory.getDVEng(session);
		
		IDVCipherSuite[] ciphers = eng.getCipherSuites();
		
		HashMap<IDVCipherSuite, IDVCipherSuite> tmap = new HashMap<IDVCipherSuite, IDVCipherSuite>();
		System.out.println("Ciphers supported by host "+url.toString());
		for( IDVCipherSuite cipher : ciphers ) {
			if( tmap.containsKey(cipher) ) {
				// If cipher's in the map then skip since we already printed it.  We only want a unique
				// list of ciphers.  API will return ciphers enumerated by handshake protocol (TLS1.0,TLS1.1,etc)
				// Comment out the lines to see the difference.  Handy if you want to track cipher suites by
				// protocol.
			}else{
				StringBuffer buff = new StringBuffer();
				buff.append(cipher.getSuiteName());
				buff.append('(');
				buff.append(cipher.getStrengthEvaluation());
				buff.append(',');
				buff.append(cipher.getHandshakeProtocol());
				buff.append(')');
				System.out.println(buff.toString());
				tmap.put(cipher, cipher);
			}
		}
		
		System.out.flush();
	
	}
	
	public static final void main(String[] args) {
		try {
			new PrintServerCiphersuites();
		}catch(Throwable t){
			t.printStackTrace();
		}
	}

}
