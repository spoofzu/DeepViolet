package com.mps.deepviolet.test.api;

import com.mps.deepviolet.api.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.File;
import java.net.URL;
import java.rmi.dgc.VMID;

import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class DVPrintTest {
	@Test
	public void injectionTest() {
		
		URL url;
		
		try {
			
			url = new URL("https://github.com/");
			IDVSession session = DVFactory.initializeSession(url);
			
			System.out.println("DVPrint tests begining");
			
			assertTrue(session != null);
			assertTrue(session.getHostInterfaces().size() > 0);
			assertTrue(session.getPropertyNames().size() > 0);
			
			IDVOnEng eng = DVFactory.getDVEng(session);
			IDVOffEng oeng = DVFactory.getDVOffEng();
			
			System.out.println("DVEPrint test starting - get host instance");
			StringBuffer con = new StringBuffer(2000);
			// If you don't need the console buff then call eng.getDVPrint()
			IDVOnPrint p = eng.getDVOnPrint(con);
			IDVOffPrint op = oeng.getDVOffPrint();
			assertTrue(p != null);
			System.out.println("DVPrint test complete - get host instance");

			System.out.println("DVEPrint test starting - print dv header");
			p.printHostInformation();
			assertTrue(con.toString().contains("[Host information]"));
			System.out.println("DVPrint test complete - print dv header");
			
			System.out.println("DVEPrint test starting - print http response headers");
			p.printHostHttpResponseHeaders();
			assertTrue(con.toString().contains("[HTTP(S) response headers]"));
			System.out.println("DVPrint test complete - print http response headers");
			
			System.out.println("DVEPrint test starting - print host information");
			p.printHostInformation();
			assertTrue(con.toString().contains("[Host information]"));
			System.out.println("DVPrint test complete - print host information");
			
			System.out.println("DVEPrint test starting - print supported ciphersuites");
			p.printSupportedCipherSuites();
			assertTrue(con.toString().contains("[Host supported server cipher suites]"));
			System.out.println("DVPrint test complete - print supported ciphersuites");
			
			System.out.println("DVEPrint test starting - print connection characteristics");
			p.printConnectionCharacteristics();
			assertTrue(con.toString().contains("[Connection characteristics]"));
			System.out.println("DVPrint test complete - print connection characteristics");
			
     	    // Test could fail for a variety of reasons, bad permissions, etc.
			System.out.println("DVEPrint test starting - write PEM encoded certificate to tmp file");
    	    VMID id = new VMID();
     	    File tpem = File.createTempFile("dvcert-"+session.getURL().getHost()+"-"+id.toString(), ".tmp");
	     	eng.writeCertificate(tpem.getAbsolutePath());	
			assertTrue(con.toString().contains("Certificate written successfully"));
			System.out.println("DVPrint test complete - write PEM encoded certificate to file");
		
     	    // Test could fail for a variety of reasons, bad permissions, etc.
			System.out.println("DVEPrint test starting - print PEM encoded certificate file");
     	    // Concievable this test could fail for a variety of reasons, bad permissions, etc.
			// Note: we are using offline engine here.  Don't need host connection print PEM file.
	     	op.printCertificate(tpem.getAbsolutePath());	
			//assertTrue(con.toString().indexOf("SubjectDN")>-1);
			System.out.println("DVPrint test complete - print PEM encoded certificate filee");
			
			System.out.println("DVEPrint test starting - print certificate chain");
			p.printServerCertificateChain();
			assertTrue(con.toString().contains("[Server certificate chain]"));
			System.out.println("DVPrint test complete - print certificate chain");
			
			//TODO printTrustState(X509Certificate), printTrustState(URL) skipped for now

			System.out.println("");
			System.out.println("**DVPrint tests successful**");
			
		} catch (Exception e) {
//			logger.error("");
//			logger.error( "DVPrint test failure. msg="+e.getMessage(),e);
//			logger.error("DVPrint tests failed");
		}
	
	}
}
