package com.mps.deepviolet.test.api;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.dgc.VMID;

import org.junit.Ignore;
import org.junit.Test;

import com.mps.deepviolet.api.DVException;
import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVOffEng;
import com.mps.deepviolet.api.IDVOffPrint;
import com.mps.deepviolet.api.IDVOnEng;
import com.mps.deepviolet.api.IDVOnPrint;
import com.mps.deepviolet.api.IDVSession;

@Ignore
public class DVPrintMultiTest {

	@Test
	public void testExpired() throws DVException, MalformedURLException {
		injectionTest("https://expired.badssl.com/");
	}

	@Test
	public void testWrongHost() throws DVException, MalformedURLException {
		injectionTest("https://wrong.host.badssl.com/");
	}

	@Test
	public void testSha1() throws DVException, MalformedURLException {
		injectionTest("https://sha1-2016.badssl.com/");
	}

	@Test
	public void testSha12017() throws DVException, MalformedURLException {
		injectionTest("https://sha1-2017.badssl.com/");
	}

	@Test
	public void testRevoked() throws DVException, MalformedURLException {
		injectionTest("https://revoked.badssl.com/");
	}

	@Test
	public void testUntrustedRoot() throws DVException, MalformedURLException {
		injectionTest("https://untrusted-root.badssl.com/");
	}

	@Test
	public void testIncompleteChain() throws DVException, MalformedURLException {
		injectionTest("https://incomplete-chain.badssl.com/");
	}

	@Test
	public void testSha256n() throws DVException, MalformedURLException {
		injectionTest("https://sha256.badssl.com/");
	}

	public void injectionTest(String host) throws MalformedURLException {

		URL url = new URL(host);
		try {

			IDVSession session = DVFactory.initializeSession(url);

			System.out.println("DVPrint tests begining");

			assertTrue(session != null);
			assertTrue(session.getHostInterfaces().length > 0);
			assertTrue(session.getPropertyNames().length > 0);

			IDVOnEng eng = DVFactory.getDVEng(session);
			IDVOffEng oeng = DVFactory.getDVOffEng();
			assertTrue(eng != null);

			System.out.println("DVEPrint test starting - get host instance");
			StringBuffer con = new StringBuffer(2000);
			// If you don't need the console buff then call eng.getDVPrint()
			IDVOnPrint p = eng.getDVOnPrint(con);
			IDVOffPrint op = oeng.getDVOffPrint();
			assertTrue(p != null);
			System.out.println("DVPrint test complete - get host instance");

			System.out.println("DVEPrint test starting - print dv header");
			p.printHostInformation();
			assertTrue(con.toString().indexOf("[Host information]") > -1);
			System.out.println("DVPrint test complete - print dv header");

			System.out.println("DVEPrint test starting - print http response headers");
			p.printHostHttpResponseHeaders();
			assertTrue(con.toString().indexOf("[HTTP(S) response headers]") > -1);
			System.out.println("DVPrint test complete - print http response headers");

			System.out.println("DVEPrint test starting - print host information");
			p.printHostInformation();
			assertTrue(con.toString().indexOf("[Host information]") > -1);
			System.out.println("DVPrint test complete - print host information");

			System.out.println("DVEPrint test starting - print supported ciphersuites");
			p.printSupportedCipherSuites();
			assertTrue(con.toString().indexOf("[Host supported server cipher suites]") > -1);
			System.out.println("DVPrint test complete - print supported ciphersuites");

			System.out.println("DVEPrint test starting - print connection characteristics");
			p.printConnectionCharacteristics();
			assertTrue(con.toString().indexOf("[Connection characteristics]") > -1);
			System.out.println("DVPrint test complete - print connection characteristics");

			// Test could fail for a variety of reasons, bad permissions, etc.
			System.out.println("DVEPrint test starting - write PEM encoded certificate to tmp file");
			VMID id = new VMID();
			File tpem = File.createTempFile("dvcert-" + session.getURL().getHost() + "-" + id.toString(), ".tmp");
			assertTrue(tpem != null);
			eng.writeCertificate(tpem.getAbsolutePath());
			assertTrue(con.toString().indexOf("Certificate written successfully") > -1);
			System.out.println("DVPrint test complete - write PEM encoded certificate to file");

			// Test could fail for a variety of reasons, bad permissions, etc.
			System.out.println("DVEPrint test starting - print PEM encoded certificate file");
			// Concievable this test could fail for a variety of reasons, bad
			// permissions, etc.
			// Note: we are using offline engine here. Don't need host
			// connection print PEM file.
			op.printCertificate(tpem.getAbsolutePath());
			// assertTrue(con.toString().indexOf("SubjectDN")>-1);
			System.out.println("DVPrint test complete - print PEM encoded certificate filee");

			System.out.println("DVEPrint test starting - print certificate chain");
			p.printServerCertificateChain();
			assertTrue(con.toString().indexOf("[Server certificate chain]") > -1);
			System.out.println("DVPrint test complete - print certificate chain");

			// TODO printTrustState(X509Certificate), printTrustState(URL)
			// skipped for now

			System.out.println("");
			System.out.println("**DVPrint tests successful**");

		} catch (Exception e) {
			// logger.error("");
			// logger.error( "DVPrint test failure. msg="+e.getMessage(),e);
			// logger.error("DVPrint tests failed");
		}

	}
}
