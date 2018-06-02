package com.mps.deepviolet.api;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * This class represents the response of a server which knows
 * SSLv2. It includes the list of cipher suites, and the
 * identification of the server certificate.
 */
class ServerHelloSSLv2 {
	int[] cipherSuites;
	String serverCertName;
	String serverCertHash;

	ServerHelloSSLv2(InputStream in)
		throws IOException
	{
		// Record length
		byte[] buf = new byte[2];
		CipherSuiteUtil.readFully(in, buf);
		int len = CipherSuiteUtil.dec16be(buf, 0);
		if ((len & 0x8000) == 0) {
			throw new IOException("not a SSLv2 record");
		}
		len &= 0x7FFF;
		if (len < 11) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		buf = new byte[11];
		CipherSuiteUtil.readFully(in, buf);
		if (buf[0] != 0x04) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		int certLen = CipherSuiteUtil.dec16be(buf, 5);
		int csLen = CipherSuiteUtil.dec16be(buf, 7);
		int connIdLen = CipherSuiteUtil.dec16be(buf, 9);
		if (len != 11 + certLen + csLen + connIdLen) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		if (csLen == 0 || csLen % 3 != 0) {
			throw new IOException(
				"not a SSLv2 server hello");
		}
		byte[] cert = new byte[certLen];
		CipherSuiteUtil.readFully(in, cert);
		byte[] cs = new byte[csLen];
		CipherSuiteUtil.readFully(in, cs);
		byte[] connId = new byte[connIdLen];
		CipherSuiteUtil.readFully(in, connId);
		cipherSuites = new int[csLen / 3];
		for (int i = 0, j = 0; i < csLen; i += 3, j ++) {
			cipherSuites[j] = CipherSuiteUtil.dec24be(cs, i);
		}
		try {
			CertificateFactory cf =
				CertificateFactory.getInstance("X.509");
			X509Certificate xc =
				(X509Certificate)cf.generateCertificate(
					new ByteArrayInputStream(cert));
			serverCertName =
				xc.getSubjectX500Principal().toString();
			serverCertHash = CipherSuiteUtil.doSHA1(cert);
		} catch (CertificateException e) {
			// ignored
		}
	}
	
}
