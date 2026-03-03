package com.mps.deepviolet.api;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Parses a TLS ServerHello handshake message from a raw input stream, extracting
 * protocol version, cipher suite, compression method, server certificate details,
 * and TLS 1.3 detection via the supported_versions extension.
 */
public class CipherSuiteUtilServerHello {

	int recordVersion;
	int protoVersion;
	long serverTime;
	int cipherSuite;
	int compression;
	String serverCertName;
	String serverCertHash;
	boolean isTLS13;

	CipherSuiteUtilServerHello(InputStream in)
		throws IOException
	{
		CipherSuiteUtilInputRecord rec = new CipherSuiteUtilInputRecord(in);
		rec.setExpectedType(CipherSuiteUtil.HANDSHAKE);

		/*
		 * First, get the handshake message header (4 bytes).
		 * First byte should be 2 ("ServerHello"), then
		 * comes the message size (over 3 bytes).
		 */
		byte[] buf = new byte[4];
		CipherSuiteUtil.readFully(rec, buf);
		recordVersion = rec.getVersion();
		if (buf[0] != 2) {
			throw new IOException("unexpected handshake"
				+ " message type: " + (buf[0] & 0xFF));
		}
		buf = new byte[CipherSuiteUtil.dec24be(buf, 1)];

		/*
		 * Read the complete message in RAM.
		 */
		CipherSuiteUtil.readFully(rec, buf);
		int ptr = 0;

		/*
		 * The protocol version which we will use.
		 */
		if (ptr + 2 > buf.length) {
			throw new IOException("invalid ServerHello");
		}
		protoVersion = CipherSuiteUtil.dec16be(buf, 0);
		ptr += 2;

		/*
		 * The server random begins with the server's notion
		 * of the current time.
		 */
		if (ptr + 32 > buf.length) {
			throw new IOException("invalid ServerHello");
		}
		serverTime = 1000L * (CipherSuiteUtil.dec32be(buf, ptr) & 0xFFFFFFFFL);
		ptr += 32;

		/*
		 * We skip the session ID.
		 */
		if (ptr + 1 > buf.length) {
			throw new IOException("invalid ServerHello");
		}
		ptr += 1 + (buf[ptr] & 0xFF);

		/*
		 * The cipher suite and compression follow.
		 */
		if (ptr + 3 > buf.length) {
			throw new IOException("invalid ServerHello");
		}
		cipherSuite = CipherSuiteUtil.dec16be(buf, ptr);
		ptr += 2;
		compression = buf[ptr] & 0xFF;
		ptr += 1;

		/*
		 * Parse extensions to detect TLS 1.3 via supported_versions.
		 * In TLS 1.3, the ServerHello version field is 0x0303 (TLS 1.2)
		 * and the actual version is in the supported_versions extension.
		 */
		isTLS13 = false;
		if (ptr + 2 <= buf.length) {
			int extTotalLen = CipherSuiteUtil.dec16be(buf, ptr);
			ptr += 2;
			int extEnd = ptr + extTotalLen;
			while (ptr + 4 <= extEnd && ptr + 4 <= buf.length) {
				int extType = CipherSuiteUtil.dec16be(buf, ptr);
				ptr += 2;
				int extLen = CipherSuiteUtil.dec16be(buf, ptr);
				ptr += 2;
				if (extType == 0x002b && extLen >= 2) {
					// supported_versions extension
					int negotiatedVersion = CipherSuiteUtil.dec16be(buf, ptr);
					if (negotiatedVersion >= 0x0304) {
						isTLS13 = true;
						protoVersion = negotiatedVersion;
					}
				}
				ptr += extLen;
			}
		}

		/*
		 * For TLS 1.3, everything after ServerHello is encrypted.
		 * We already have the cipher suite, so return without trying
		 * to read Certificate or other messages.
		 */
		if (isTLS13) {
			return;
		}

		/*
		 * We now read a few extra messages, until we
		 * reach the server's Certificate message, or
		 * ServerHelloDone.
		 */
		for (;;) {
			buf = new byte[4];
			CipherSuiteUtil.readFully(rec, buf);
			int mt = buf[0] & 0xFF;
			buf = new byte[CipherSuiteUtil.dec24be(buf, 1)];
			CipherSuiteUtil.readFully(rec, buf);
			switch (mt) {
			case 11:
				processCertificate(buf);
				return;
			case 14:
				// ServerHelloDone
				return;
			}
		}
	}

	private void processCertificate(byte[] buf)
	{
		if (buf.length <= 6) {
			return;
		}
		int len1 = CipherSuiteUtil.dec24be(buf, 0);
		if (len1 != buf.length - 3) {
			return;
		}
		int len2 = CipherSuiteUtil.dec24be(buf, 3);
		if (len2 > buf.length - 6) {
			return;
		}
		byte[] ec = new byte[len2];
		System.arraycopy(buf, 6, ec, 0, len2);
		try {
			CertificateFactory cf =
				CertificateFactory.getInstance("X.509");
			X509Certificate xc =
				(X509Certificate)cf.generateCertificate(
					new ByteArrayInputStream(ec));
			serverCertName =
				xc.getSubjectX500Principal().toString();
			serverCertHash = CipherSuiteUtil.doSHA1(ec);
		} catch (CertificateException e) {
			// ignored
			return;
		}
	}
}
