package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

// FYI - This test needs to be reviewed.
// See following build, https://travis-ci.org/spoofzu/DeepViolet/builds/179650091
@Disabled("Requires network access - needs review")
public class DeepVioletEngineTest {

	private IEngine e;
	private ISession session;

	@BeforeEach
	public void setup() throws MalformedURLException, DeepVioletException {
		session = DeepVioletFactory.initializeSession(new URL("https://www.badssl.com"));
		e = DeepVioletFactory.getEngine(session);
	}

	@AfterEach
	public void tearDown() {
		session = null;
		e = null;
	}

	@Test
	public void testGetCipherSuites() throws DeepVioletException {
		assertEquals(16, e.getCipherSuites().length);
		for (ICipherSuite c : e.getCipherSuites()) {
			System.out.println("CipherSuite: name=" + c.getSuiteName() + " strengtheEvaluation=" + c.getStrengthEvaluation());
		}
	}

	@Test
	public void testGetCertificate() throws DeepVioletException {
		IX509Certificate cert = e.getCertificate();
		assertEquals(
				"25:FE:39:32:D9:63:8C:8A:FC:A1:9A:29:87:D8:3E:4C:1D:98:DB:71:E4:1A:48:03:98:EA:22:6A:BD:8B:93:16",
				cert.getCertificateFingerPrint());
	}

	@Disabled("Requires network access")
	@Test
	public void testWriteCertificate() throws IOException, DeepVioletException {
		String certFile = File.createTempFile("DVEndTest", "pem")
				.getAbsolutePath();
		long length = e.writeCertificate(certFile);
		System.out.println(length);
	}
}
