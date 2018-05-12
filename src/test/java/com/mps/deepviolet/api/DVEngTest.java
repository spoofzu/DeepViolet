package com.mps.deepviolet.api;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

// FYI - This test needs to be reviewed.
// See following build, https://travis-ci.org/spoofzu/DeepViolet/builds/179650091
@Ignore
public class DVEngTest {

	private IDVEng e;
	private IDVSession session;

	@Before
	public void setup() throws MalformedURLException, DVException {
		session = DVFactory.initializeSession(new URL("https://github.com"));
		e = DVFactory.getDVEng(session);
	}

	@After
	public void tearDown() {
		session = null;
		e = null;
	}

	@Test
	public void testGetCipherSuites() throws DVException {
		assertEquals(16, e.getCipherSuites().length);
		for ( IDVCipherSuite c : e.getCipherSuites() ) {
			System.out.println("CipherSuite: name="+c.getSuiteName()+" strengtheEvaluation="+c.getStrengthEvaluation() );
		}
	}

	@Test
	public void testGetCertificate() throws DVException {
		IDVX509Certificate cert = e.getCertificate();
		assertEquals(
				"25:FE:39:32:D9:63:8C:8A:FC:A1:9A:29:87:D8:3E:4C:1D:98:DB:71:E4:1A:48:03:98:EA:22:6A:BD:8B:93:16",
				cert.getCertificateFingerPrint());
	}

	// @Test
	public void testWriteCertificate() throws IOException, DVException {
		String certFile = File.createTempFile("DVEndTest", "pem")
				.getAbsolutePath();
		long length = e.writeCertificate(certFile);
		System.out.println(length);
	}
}
