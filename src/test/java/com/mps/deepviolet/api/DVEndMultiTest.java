package com.mps.deepviolet.api;

import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class DVEndMultiTest {

	@Test
	public void testExpired() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://expired.badssl.com/");
	}

	@Test
	public void testWrongHost() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://wrong.host.badssl.com/");
	}

	@Test
	public void testSha1() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://sha1-2016.badssl.com/");
	}

	@Test
	public void testSha12017() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://sha1-2017.badssl.com/");
	}

	@Test
	public void testRevoked() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://revoked.badssl.com/");
	}

	@Test
	public void testUntrustedRoot() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://untrusted-root.badssl.com/");
	}

	@Test
	public void testIncompleteChain() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://incomplete-chain.badssl.com/");
	}

	@Test
	public void testSha256n() throws DVException, MalformedURLException {
		testSpecificSSLConfig("https://sha256.badssl.com/");
	}

	public void testSpecificSSLConfig(String url) throws DVException, MalformedURLException {
		IDVSession session = DVFactory.initializeSession(new URL(url));
		DVEng e = new DVEng(session);
		System.out.println("ID = " + session.getIdentity());

		IDVHost[] ifs = session.getHostInterfaces();
		System.out.println("Interfaces : ");
		for (int i = 0; i < ifs.length; i++) {
			System.out.println(ifs[i].getHostCannonicalName());
		}

		System.out.println("prop names : ");
		IDVSession.SESSION_PROPERTIES[] names = session.getPropertyNames();
		for (int i = 0; i < names.length; i++) {
			System.out.print(names[i] + " = ");
			System.out.println(session.getPropertyValue(names[i]));
		}
		assertEquals(36, e.getCipherSuites().length);
	}

}
