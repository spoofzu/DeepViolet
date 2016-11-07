package com.mps.deepviolet.api.samples;

import java.net.URL;

import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVOnEng;
import com.mps.deepviolet.api.IDVOnPrint;
import com.mps.deepviolet.api.IDVSession;

/**
 * Convienence method for printing simple output to a console buffer.
 * 
 * @author Milton Smith
 *
 */
public class PrintHostReport {

	public PrintHostReport() throws Exception {

		URL url = new URL("https://github.com/");
		IDVSession session = DVFactory.initializeSession(url);
		IDVOnEng eng = DVFactory.getDVEng(session);

		// If you don't need the console buff then call eng.getDVPrint()
		StringBuffer con = new StringBuffer(2000);
		IDVOnPrint host_print_instance = eng.getDVOnPrint(con);

		// Print some different sections.
		con.append("Step 1 of 5: Host information section");
		host_print_instance.printHostInformation();
		
		con.append("Step 2 of 5: Host HTTP response");
		host_print_instance.printHostHttpResponseHeaders();
		
		con.append("Step 3 of 5: Host supported ciphers");
		host_print_instance.printSupportedCipherSuites();
		
		con.append("Step 4 of 5: Host connection characteristics");
		host_print_instance.printConnectionCharacteristics();
		
		con.append("Step 5 of 5: Host certificate chain");
		host_print_instance.printServerCertificateChain();

		// This message would be missed since no more sections are
		// being printed. Need to call println explicitlly.
		con.append("Finished!");
		host_print_instance.println(con.toString());
	}

	public static final void main(String[] args) {
		try {
			new PrintHostReport();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

}
