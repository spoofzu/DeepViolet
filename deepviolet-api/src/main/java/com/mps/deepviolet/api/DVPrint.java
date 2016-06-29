package com.mps.deepviolet.api;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLHandshakeException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.suite.CipherSuiteUtil;

/**
 * Report utility that controls how each report section is printed.
 * 
 * @author Milton Smith
 */
class DVPrint implements IDVOnPrint, IDVOffPrint {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolet.ui.DocPrintUtil");
	private final String EOL = System.getProperty("line.separator");

	protected static HashMap<String, DVPrint> dvHostMap = new HashMap<String, DVPrint>();

	protected StringBuffer con;
	protected IDVHost[] dvHosts;
	protected IDVSession session;
	protected IDVOnEng eng;
	protected IDVOffEng oeng;
	protected IDVX509Certificate dvCert;

	protected DVPrint() {

	}

	/*
	 * (non-Javadoc)
	 */
	DVPrint(IDVOnEng eng, StringBuffer con) throws DVException {
		this.eng = eng;
		this.dvCert = eng.getCertificate();
		this.oeng = DVFactory.getDVOffEng();
		this.dvHosts = eng.getDVSession().getHostInterfaces();
		this.session = eng.getDVSession();
		this.con = con;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printReportHeader()
	 */
	public void printReportHeader() {

		Date d = new Date();
		println("");
		println("***********************************************************************");
		println("***********************************************************************");
		println("*  NOTICE: THIS SOFTWARE IS PROVIDED FOR RESEARCH PURPOSES AND NOT     ");
		println("*          RECOMMENDED FOR USE ON PRODUCTION SYSTEMS.  SEE PROJECT     ");
		println("*          INFORMATION ON GITHUB FOR FURTHER DETAILS,                  ");
		println("*          https://github.com/spoofzu/DeepViolet                       ");
		println("***********************************************************************");
		println("***********************************************************************");
		println("");
		println("[Report run information]");
		println("DeepViolet " + oeng.getDeepVioletStringVersion());
		println("Report generated on " + d.toString());
		if (session.getURL() != null) {
			println("Target url " + session.getURL().toString());
		}
		// TODO: PRINT THE LOGBACK FILE LOCATION, LOCATION OF CACERTS, AND
		// VERSION OF JAVA

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printHostHttpResponseHeaders()
	 */
	public void printHostHttpResponseHeaders() {

		println("");
		println("[HTTP(S) response headers]");

		try {

			Map<String, List<String>> headers = CipherSuiteUtil
					.getHttpResponseHeaders(session.getURL());

			for (Map.Entry<String, List<String>> entry : headers.entrySet()) {

				String key = (String) entry.getKey();

				List<String> vlist = entry.getValue();

				for (String value : vlist) {

					key = (key == null) ? "<null>" : key;
					key = (key.length() > 5000) ? key.substring(0, 5000)
							+ "[truncated by DeepViolet sz=" + key.length()
							+ "]" : key;

					value = (value == null) ? "<null>" : value;
					value = (value.length() > 5000) ? value.substring(0, 5000)
							+ "[truncated by DeepViolet sz=" + key.length()
							+ "]" : value;

					println(key + " : " + value);

				}

			}

		} catch (SSLHandshakeException e) {

			if (e.getMessage().indexOf("PKIX") > 0) {
				println("Certificate chain failed validation.");
				println("");
				logger.error(
						"Certificate chain failed validation. err="
								+ e.getMessage(), e);
			} else {
				println("SSLHandshakeException. err=" + e.getMessage());
				println("");
				logger.error("SSLHandshakeException. err=" + e.getMessage(), e);
			}

		} catch (Exception e) {

			println("Error printing HTTP headers. err=" + e.getMessage());
			println("");
			logger.error("Error printing HTTP headers. err=" + e.getMessage(),
					e);

		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printHostInformation()
	 */
	public void printHostInformation() {

		println("");
		println("[Host information]");

		try {

			IDVHost[] hosts = this.dvHosts;

			for (IDVHost host : hosts) {

				StringBuffer buff = new StringBuffer();
				buff.append("host=" + host.getHostName() + " ["
						+ host.getHostIPAddress() + "], ");
				buff.append("canonical=" + host.getHostCannonicalName());
				println(buff.toString());

			}

		} catch (Exception e) {
			println("Can't fetch host. err=" + e.getMessage());
			println("");
			logger.error("Can't fetch host. err=" + e.getMessage(), e);
		}

	}

	// // TODO: NOT USED AT THE MOMENT
	// public static final void printServerAnalysis() {
	//
	// DocPrintUtil.println("[Server analysis]");
	// DocPrintUtil.println("DISABLED, Uncomment code and recompile to experiment.");
	//
	// try {
	//
	// ServerMetadata m = CipherSuiteUtil.getServerMetadataInstance(url);
	//
	// //TODO: Displays scalar properties but skips any vector quantities (but
	// no vector quantities for now)
	// for (String key : m.getKeys("analysis")) {
	//
	// if( m.isScalarType("analysis", key) )
	// DocPrintUtil.println( key+"="+m.getScalarValue("analysis",key));
	//
	// }
	//
	// } catch (Exception e) {
	// DocPrintUtil.println("Can't perform server analysis. err="+e.getMessage()
	// );
	// DocPrintUtil.println("");
	// logger.error("Can't perform server analysis. err="+e.getMessage(),e);
	// }
	//
	// }

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printSupportedCipherSuites()
	 */
	public void printSupportedCipherSuites() {

		println("");
		println("[Host supported server cipher suites]");

		try {

			IDVHost[] hosts = this.dvHosts;

			if (hosts != null) {

				IDVCipherSuite[] ciphers = eng.getCipherSuites();
				HashMap<String, String> tmap = new HashMap<String, String>();

				for (IDVCipherSuite cipher : ciphers) {

					if (tmap.containsKey(cipher.getIANAName())) {
						// If the cipher belongs to another handshake
						// protcol then skip. Only want uniquely named
						// ciphersuites.
					} else {
						StringBuffer buff = new StringBuffer();
						buff.append(cipher.getIANAName());
						buff.append(" (");
						buff.append(cipher.getStrengthEvaluation());
						buff.append(',');
						buff.append(cipher.getHandshakeProtocol());
						buff.append(')');
						println(buff.toString());
						tmap.put(cipher.getIANAName(),
								cipher.getStrengthEvaluation());
					}

				}

			} else {

				println("Problem fetching host ciphersuites.  See log for details.");
				logger.error("Problem processing server ciphers. err=hosts null");

			}

		} catch (Exception e) {
			println("Problem processing server ciphers. err=" + e.getMessage());
			println("");
			logger.error(
					"Problem processing server ciphers. err=" + e.getMessage(),
					e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printConnectionCharacteristics()
	 */
	public void printConnectionCharacteristics() {

		println("");
		println("[Connection characteristics]");

		IDVHost[] dvhosts = this.dvHosts;

		if (dvhosts.length < 1) {
			println("No host data returned. err=dvhost is null");
			return;
		}

		String[] connection_properties = session.getPropertyNames();
		for (String key : connection_properties) {

			println(key + "=" + session.getPropertyValue(key));

		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printCertificate(java.lang.String)
	 */
	public void printCertificate(String file) {

		try {
			File f = new File(file);
			FileInputStream fs = new FileInputStream(f);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Collection<? extends Certificate> c = cf.generateCertificates(fs);
			Iterator<? extends Certificate> i = c.iterator();

			while (i.hasNext()) {
				X509Certificate lcert = (X509Certificate) i.next();
				DVX509OffCertificate ldvCert = new DVX509OffCertificate(eng,
						lcert);
				printTrustState(ldvCert);
				printX509Certificate(ldvCert);
			}

		} catch (DVException e) {
			println("Read certificate failed. reason=" + e.getMessage()
					+ " file=" + file);
			println("");
		} catch (FileNotFoundException e) {
			println("Read certificate failed. reason=file not found.  file="
					+ file);
			println("");
		} catch (CertificateException e) {
			println("Read certificate failed.  reason=" + e.getMessage()
					+ " file=" + file);
			println("");
			logger.error("Read certificate failed.  reason=" + e.getMessage()
					+ " file=" + file);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printTrustState()
	 */
	private void printTrustState(IDVX509Certificate ldvCert) {

		String trust_state = "<ERROR>";
		if (ldvCert.getTrustState() == IDVX509Certificate.TRUST_STATE_TRUSTED) {
			trust_state = "TRUSTED";
		} else if (ldvCert.getTrustState() == IDVX509Certificate.TRUST_STATE_UNKNOWN) {
			trust_state = "UNKNOWN";
		} else if (ldvCert.getTrustState() == IDVX509Certificate.TRUST_STATE_UNTRUSTED) {
			trust_state = "UNTRUSTED";
		}

		StringBuffer buff = new StringBuffer();
		buff.append("Trusted State=");
		boolean trusted = trust_state
				.equals(IDVX509Certificate.TRUST_STATE_TRUSTED);

		if (trusted) {
			buff.append("trusted");
		} else {
			buff.append(">>>");
			buff.append(trust_state);
			buff.append("<<<");
		}
		println(buff.toString());

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printServerCertificate()
	 */
	public void printServerCertificate() {

		println("");
		println("[Server certificate information]");

		printTrustState(dvCert);

		printX509Certificate(dvCert);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.mps.deepviolet.api.IDVPrint#printServerCertificateChain()
	 */
	public void printServerCertificateChain() {

		println("[Server certificate chain]");

		StringBuffer buff = new StringBuffer();

		println("Chain Summary, end-entity --> root");

		IDVX509Certificate[] certs;

		try {
			certs = dvCert.getCertificateChain();
			boolean firstcert = true;
			int n = 0;
			IDVX509Certificate last_cert = null;

			for (IDVX509Certificate ldvCert : certs) {

				if (ldvCert.isSelfSignedCertificate()) {
					break;
				}

				println(buff.toString() + "|");
				println(buff.toString() + "|");

				StringBuffer attributes = new StringBuffer();

				attributes.append("NODE" + n + "(");

				if (firstcert) {
					attributes.append("End-Entity ");
				} else {
					attributes.append("Intermediate CA ");
				}

				attributes.append(")--->");
				attributes.append("SubjectDN=" + ldvCert.getSubjectDN()
						+ " IssuerDN=" + ldvCert.getIssuerDN());
				attributes.append(", " + ldvCert.getSigningAlgorithm()
						+ "(Fingerprint)="
						+ ldvCert.getCertificateFingerPrint());

				println(buff.toString() + attributes.toString());

				firstcert = false;
				buff.append("   ");
				n++;
				last_cert = ldvCert;

			}

			println(buff.toString() + "|");
			println(buff.toString() + "|");
			buff.append("NODE" + n + "(");

			if (last_cert.isJavaRootCertificate()) {
				buff.append("Java Root CA ");
			} else {
				buff.append("Self-Signed CA ");
			}

			buff.append(")--->");
			buff.append("SubjectDN=" + last_cert.getSubjectDN());

			buff.append(", " + last_cert.getSigningAlgorithm()
					+ "(Fingerprint)=" + last_cert.getCertificateFingerPrint());

			println(buff.toString());

			buff = new StringBuffer();

			println("");
			println("[Chain details]");

			int n1 = 0;
			for (IDVX509Certificate ldvCert : certs) {
				println("[NODE" + n1 + "] ");
				printX509Certificate(ldvCert);
				n1++;
			}

		} catch (Exception e) {
			println("Problem fetching certificates. err=" + e.getMessage());
			println("");
			logger.error(
					"Problem fetching certificates. err=" + e.getMessage(), e);
		}

	}

	/**
	 * Print a IDVX509Certificate instance.
	 * 
	 * @param ldvCert
	 *            Host certificate to print
	 */
	private final void printX509Certificate(IDVX509Certificate ldvCert) {

		logger.trace(ldvCert.toString());

		String not_before = ldvCert.getNotValidBefore();
		String not_after = ldvCert.getNotValidAfter();
		int validity_state = ldvCert.getValidityState();

		if (validity_state == IDVX509Certificate.VALID_STATE_VALID) {
			println("Validity Check=VALID, certificate valid between "
					+ not_before + " and " + not_after);
		} else if (validity_state == IDVX509Certificate.VALID_STATE_NOT_YET_VALID) {
			println("Validity Check=>>>NOT YET VALID<<<, certificate valid between "
					+ not_before + " and " + not_after);
		} else if (validity_state == IDVX509Certificate.VALID_STATE_EXPIRED) {
			println("Validity Check=>>>EXPIRED<<<, certificate valid between "
					+ not_before + " and " + not_after);
		}

		String subject_dn = ldvCert.getSubjectDN();
		String issuer_dn = ldvCert.getIssuerDN();
		String serial_number = ldvCert.getCertificateSerialNumber().toString();
		String signature_algo = ldvCert.getSigningAlgorithm();
		String signature_algo_oid = ldvCert.getSigningAlgorithmOID();
		String certificate_ver = Integer.toString(ldvCert
				.getCertificateVersion());
		println("SubjectDN=" + subject_dn);
		println("IssuerDN=" + issuer_dn);
		println("Serial Number=" + serial_number);
		println("Signature Algorithm=" + signature_algo);
		println("Signature Algorithm OID=" + signature_algo_oid);
		println("Certificate Version =" + certificate_ver);

		String digest_algo = signature_algo.substring(0,
				signature_algo.indexOf("with"));
		String fingerprint = ldvCert.getCertificateFingerPrint();
		println(digest_algo + "(Fingerprint)=" + fingerprint);

		println("Non-critical OIDs");
		printNonCritOIDs(ldvCert);

		println("Critical OIDs");
		printCritOIDs(ldvCert);

		println("");

	}

	/**
	 * Print a list of non-critical OIDs.
	 * 
	 * @param ldvCert
	 *            Host certificate
	 */
	private final void printNonCritOIDs(IDVX509Certificate ldvCert) {

		String[] keys = ldvCert.getNonCritOIDProperties();

		for (String key : keys) {
			String value = ldvCert.getNonCritPropertyValue(key);
			println(key + "=" + value);
		}

	}

	/**
	 * Print a list of critical OIDs.
	 * 
	 * @param ldvCert
	 *            Host certificate
	 */
	private final void printCritOIDs(IDVX509Certificate ldvCert) {

		String[] keys = ldvCert.getCritOIDProperties();

		for (String key : keys) {
			String value = ldvCert.getCritPropertyValue(key);
			println(key + "=" + value);
		}

	}

	/**
	 * End of Line(EOL) for active operating system
	 * 
	 * @return EOL sequence.
	 */
	public final String getEOL() {
		return EOL;
	}

	/**
	 * Output a single line of text to buffer with line feed.
	 * 
	 * @param text
	 *            Print line of text to console buffer.
	 */
	public final void println(String text) {

		con.append(text);
		con.append(EOL);

		logger.info(text);

	}

}
