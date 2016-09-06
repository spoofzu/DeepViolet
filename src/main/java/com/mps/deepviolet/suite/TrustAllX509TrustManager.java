package com.mps.deepviolet.suite;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * A SSL\TLS trust manager that trusts all X509 certs.  Necessary so we can
 * receive and examine metadata for bad certificates. 
 * @author Milton
 * @see http://stackoverflow.com/questions/19723415/java-overriding-function-to-disable-ssl-certificate-check
 */
@SuppressWarnings("JavadocReference")
public class TrustAllX509TrustManager implements X509TrustManager {

	public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
	}

	public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }

	public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
}
	
