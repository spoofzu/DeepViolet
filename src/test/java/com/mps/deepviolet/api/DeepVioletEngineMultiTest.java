package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("Requires network access to badssl.com endpoints")
public class DeepVioletEngineMultiTest {

	@Test
	public void testExpired() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://expired.badssl.com/");
	}

	@Test
	public void testWrongHost() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://wrong.host.badssl.com/");
	}

	@Test
	public void testSha1() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://sha1-2016.badssl.com/");
	}

	@Test
	public void testSha12017() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://sha1-2017.badssl.com/");
	}

	@Test
	public void testRevoked() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://revoked.badssl.com/");
	}

	@Test
	public void testUntrustedRoot() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://untrusted-root.badssl.com/");
	}

	@Test
	public void testIncompleteChain() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://incomplete-chain.badssl.com/");
	}

	@Test
	public void testSha256n() throws DeepVioletException, MalformedURLException {
		testSpecificSSLConfig("https://sha256.badssl.com/");
	}

	public void testSpecificSSLConfig(String url) throws DeepVioletException, MalformedURLException {
		ISession session = DeepVioletFactory.initializeSession(new URL(url));
		IEngine e = DeepVioletFactory.getEngine(session);
		System.out.println("ID = " + session.getIdentity());

		IHost[] ifs = session.getHostInterfaces();
		System.out.println("Interfaces : ");
		for (int i = 0; i < ifs.length; i++) {
			System.out.println(ifs[i].getHostCannonicalName());
		}

		System.out.println("prop names : ");
		for (ISession.SESSION_PROPERTIES name : ISession.SESSION_PROPERTIES.values()) {
			System.out.print(name + " = ");
			System.out.println(session.getSessionPropertyValue(name));
		}

		assertEquals(36, e.getCipherSuites().length);
	}

}
