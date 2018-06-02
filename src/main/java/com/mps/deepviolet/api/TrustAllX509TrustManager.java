package com.mps.deepviolet.api;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * A SSL\TLS trust manager that trusts all X509 certs.  Necessary so we can
 * receive and examine metadata for bad certificates. 
 * For more information see, 
 * <a href="http://stackoverflow.com/questions/19723415/java-overriding-function-to-disable-ssl-certificate-check">Java: Overriding function to disable SSL certificate check</a>
 * @author Milton Smith
 */
class TrustAllX509TrustManager implements X509TrustManager {

	public X509Certificate[] getAcceptedIssuers() {
	        return new X509Certificate[0];
    }

    public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
            String authType) {
    }

    public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
            String authType) {
    }

}
	
