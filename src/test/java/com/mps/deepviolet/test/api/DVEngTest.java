package com.mps.deepviolet.test.api;

import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.List;

import com.mps.deepviolet.api.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class DVEngTest {
	
	@Before
	public void setup() {
		
	}
	
	@After
	public void teardown() {
		
	}
	
	@Test
	public void injectionTest() {
		

		URL url;
		try {
			
			System.out.println("DVEng tests begining");
			
			System.out.println("DVEng test starting - host init");
			url = new URL("https://github.com/");
			
			IDVSession session = DVFactory.initializeSession(url);
			assertTrue(session != null);
			assertTrue(session.getHostInterfaces().size() > 0);
			assertTrue(session.getPropertyNames().size() > 0);
			
			IDVOnEng eng = DVFactory.getDVEng(session);
			IDVOffEng oeng = DVFactory.getDVOffEng();
			System.out.println("DVEng test complete - host init");
			
			System.out.println("DVEng test starting - version string");
			String sVersion = oeng.getDeepVioletStringVersion();
			assertTrue(sVersion != null);
			assertTrue(sVersion.length()>0);
			assertTrue(sVersion.indexOf('V') > -1 );
			System.out.println("DVEng test complete - version string");
			
			System.out.println("DVEng test starting - cipher suites");
			List<IDVCipherSuite> ciphers = eng.getCipherSuites();
			assertTrue(ciphers != null);
			assertTrue(ciphers.size() > 0);
			System.out.println("DVEng test complete - cipher suites");
			
			System.out.println("DVEng test starting - get host certificate");
			IDVX509Certificate dvCert = eng.getCertificate();
			assertTrue(dvCert != null);
			assertTrue(dvCert.getSubjectDN().length() > 0);
			System.out.println(dvCert.toString());
			System.out.println("DVEng test complete - get host certificate");
			
			System.out.println("DVEng test starting - get host certificate chain");
			List<IDVX509Certificate> chain = dvCert.getCertificateChain();
			IDVX509Certificate last_cert = null;
			int node = 0;
			for(IDVX509Certificate ldvCert: chain ) {
				System.out.println("[NODE"+node+"]");
				System.out.println(ldvCert.toString());
				System.out.println("");
				last_cert = ldvCert;
				node++;
			}
			assertTrue(last_cert != null);
			assertTrue(last_cert.getSubjectDN().length()  > 0);
			assertTrue(last_cert.isJavaRootCertificate());
			System.out.println("DVEng test complete - get host certificate chain");
			
			System.out.println("DVEng tests successful");
			
		} catch (Exception e) {
			System.out.println( "DVEng test failure. msg=");
			System.out.println("DVEng tests failed");
			e.printStackTrace();
		}
		
	}
	
}
