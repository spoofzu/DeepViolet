package com.mps.deepviolet.api;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Base64;
import java.util.TreeSet;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

import com.mps.deepviolet.api.tls.ClientHelloConfig;
import com.mps.deepviolet.api.tls.TlsMetadata;
import com.mps.deepviolet.api.tls.TlsSocket;
import com.mps.deepviolet.util.DerParser;

/**
 * Utility class to handle cryptographic functions.  Significant contributions around
 * cipher suite handling adapted from code examples by <a href="mailto:pornin@bolet.org">Thomas Pornin</a>.
 * For more information see, <a href="http://tools.ietf.org/html/rfc5246">The Transport Layer Security (TLS) Protocol Version 1.2</a>,
 * <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml">Transport Layer Security (TLS) Parameters</a>,
 * <a href="http://www.bolet.org/TestSSLServer/">TestSSLServer</a>
 * @author Milton Smith
 */
class CipherSuiteUtil {

// Handshake protocol version legend
//	SSL v1
//	SSL v2
//	SSL v3
//	SSL v3.1 = TLS v1.0
//	SSL v3.2 = TLS v1.1
//	SSL v3.3 = TLS v1.2
	
	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.suite.CipherSuiteUtil");
	
	// Common OIDs to Extension Mappings
	private static final HashMap<String,String> OIDMAP = new HashMap<String,String>();
	
	private static final SSLSocketFactory dsc = HttpsURLConnection.getDefaultSSLSocketFactory();
	
	private static final HostnameVerifier dhv = HttpsURLConnection.getDefaultHostnameVerifier();
	
	static final int MAX_RECORD_LEN = 16384;
	static final int CHANGE_CIPHER_SPEC = 20;
	static final int ALERT              = 21;
	static final int HANDSHAKE          = 22;
	static final int APPLICATION        = 23;
	private static final SecureRandom RNG = new SecureRandom();

	private static final int CONNECT_TIMEOUT_MS = 10_000;  // 10 seconds
	private static final int READ_TIMEOUT_MS = 10_000;      // 10 seconds

	private static final byte[] SSL2_CLIENT_HELLO = {
		(byte)0x80, (byte)0x2E,  // header (record length)
		(byte)0x01,              // message type (CLIENT HELLO)
		(byte)0x00, (byte)0x02,  // version (0x0002)
		(byte)0x00, (byte)0x15,  // cipher specs list length
		(byte)0x00, (byte)0x00,  // session ID length
		(byte)0x00, (byte)0x10,  // challenge length
		0x01, 0x00, (byte)0x80,  // SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, (byte)0x80,  // SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x03, 0x00, (byte)0x80,  // SSL_CK_RC2_128_CBC_WITH_MD5
		0x04, 0x00, (byte)0x80,  // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		0x05, 0x00, (byte)0x80,  // SSL_CK_IDEA_128_CBC_WITH_MD5
		0x06, 0x00, (byte)0x40,  // SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, (byte)0xC0,  // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		0x54, 0x54, 0x54, 0x54,  // challenge data (16 bytes)
		0x54, 0x54, 0x54, 0x54,
		0x54, 0x54, 0x54, 0x54,
		0x54, 0x54, 0x54, 0x54
	};
	
	static final int UNASSIGNED = -1; // no evaluation in json mapping file
	static final int CLEAR  = 0; // no encryption
	static final int WEAK   = 1; // weak encryption: 40-bit key
	static final int MEDIUM = 2; // medium encryption: 56-bit key
	static final int STRONG = 3; // strong encryption
	public static final String NO_CIPHERS = "No Ciphers";	
	static Map<Integer, CipherSuite> CIPHER_SUITES =
			new TreeMap<Integer, CipherSuite>();
	
	
	static volatile boolean bCiphersInitialized = false;
	private static final Object CIPHER_INIT_LOCK = new Object();
	private static final Object TLS_CHAIN_TESTING_LOCK = new Object();

	/**
	 * Thread-safe cipher map initialization using double-checked locking.
	 */
	static void ensureCipherMapInitialized() {
		if (!bCiphersInitialized) {
			synchronized (CIPHER_INIT_LOCK) {
				if (!bCiphersInitialized) {
					initCipherMap();
				}
			}
		}
	}

	static {
		// OID mappings for extension parsing
		OIDMAP.put( "2.5.29.14","SubjectKeyIdentifier");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		OIDMAP.put( "2.5.29.16","PrivateKeyUsage");
		OIDMAP.put( "2.5.29.17","SubjectAlternativeName");
		OIDMAP.put( "2.5.29.18","IssuerAlternativeName");
		OIDMAP.put( "2.5.29.19","BasicConstraints");
		OIDMAP.put( "2.5.29.30","NameConstraints");
		OIDMAP.put( "2.5.29.33","PolicyMappings");
		OIDMAP.put( "2.5.29.35","AuthorityKeyIdentifier");
		OIDMAP.put( "2.5.29.36","PolicyConstraints");
		
		OIDMAP.put( "1.3.6.1.5.5.7.48.1","ocsp");
		OIDMAP.put( "1.3.6.1.5.5.7.48.2","caIssuers");
		OIDMAP.put( "1.2.840.113549.1.1.1","SubjectPublicKeyInfo");
		OIDMAP.put( "1.3.6.1.5.5.7.48.1.1","BasicOCSPResponse");
		OIDMAP.put( "1.2.840.113549.1.1.5","SignatureAlgorithm");
		OIDMAP.put( "1.3.6.1.5.5.7.1.1","AuthorityInfoAccess");
		OIDMAP.put("1.3.6.1.4.1.11129.2.4.2", "SignedCertificateTimestampList");
		OIDMAP.put("1.3.6.1.5.5.7.2.2", "CPSUserNotice");
		OIDMAP.put( "2.5.29.31","CRLDistributionPoints");
		OIDMAP.put( "2.5.29.32","CertificatePolicies");
		OIDMAP.put( "1.3.6.1.4.1.6449.1.2.1.5.1","CertificatePolicyId");
		OIDMAP.put( "2.5.29.32","CertificatePolicies");
		OIDMAP.put( "1.3.6.1.5.5.7.2.1","qualifierID");
		OIDMAP.put( "2.5.29.37","ExtendedKeyUsages");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		OIDMAP.put( "2.5.29.14","SubjectKeyIdentifier");
		
	}
		
	// TODO This needs to go bye bye, a bad idea.  I'm thinking a better way to do this is eventually
	// get to a MVC type architecture.  This would better address the ways deepviolet can be used
	/**
	 * Probe the target server for supported TLS/SSL versions and cipher suites, returning
	 * the collected metadata.
	 * @param url target server URL
	 * @param cipher_name_convention naming convention to use for cipher suite names (IANA, OpenSSL, etc.)
	 * @param session mutable session to store discovered properties (e.g., compression support)
	 * @param dvtask background task for status-bar progress updates
	 * @return ServerMetadata containing protocol versions and cipher suites, or null if the server is not TLS-enabled
	 * @throws Exception on connection or analysis errors
	 */
	static ServerMetadata getServerMetadataInstance( URL url, ISession.CIPHER_NAME_CONVENTION cipher_name_convention, MutableSession session, BackgroundTask dvtask ) throws Exception {
		return getServerMetadataInstance(url, cipher_name_convention, session, dvtask, null);
	}

	/**
	 * Probe the target server for supported TLS/SSL versions and cipher suites, returning
	 * the collected metadata.  When {@code enabledProtocols} is non-null and non-empty,
	 * only the specified protocol versions are probed.
	 * @param url target server URL
	 * @param cipher_name_convention naming convention to use for cipher suite names (IANA, OpenSSL, etc.)
	 * @param session mutable session to store discovered properties (e.g., compression support)
	 * @param dvtask background task for status-bar progress updates
	 * @param enabledProtocols set of protocol version codes to probe (e.g. 0x0303 for TLS 1.2), or null for all
	 * @return ServerMetadata containing protocol versions and cipher suites, or null if the server is not TLS-enabled
	 * @throws Exception on connection or analysis errors
	 */
	static ServerMetadata getServerMetadataInstance( URL url, ISession.CIPHER_NAME_CONVENTION cipher_name_convention, MutableSession session, BackgroundTask dvtask, Set<Integer> enabledProtocols ) throws Exception {

		HostData hostdata = new HostData(url);;
		Boolean compress = false;

		// Generate cipher map dynamically based upon Mozilla json data.
		dvtask.setStatusBarMessage("Initializing DV cipher suite maps");
		ensureCipherMapInitialized();

		dvtask.setStatusBarMessage("Reviewing server protocols");

		String name = url.getHost();
		int port = ( url.getPort() > 0 ) ? url.getPort() : 443;

		InetSocketAddress isa = new InetSocketAddress(name, port);

		Set<Integer> sv = new TreeSet<Integer>();
		for (int v = 0x0300; v <= 0x0304; v ++) {
			dvtask.waitIfPaused();
			if (dvtask.isCancelled()) return null;
			if (enabledProtocols != null && !enabledProtocols.isEmpty()
					&& !enabledProtocols.contains(v)) {
				continue;
			}
			CipherSuiteUtilServerHello sh = connect(isa,
				v, CIPHER_SUITES.keySet());
			if (sh == null) {
				continue;
			}
			// The server may respond with a different version than requested
			// (e.g. TLS 1.3 ClientHello → TLS 1.2 ServerHello fallback).
			// If the response version is outside the enabled set, skip it.
			if (enabledProtocols != null && !enabledProtocols.isEmpty()
					&& !enabledProtocols.contains(sh.protoVersion)) {
				continue;
			}
			sv.add(sh.protoVersion);
			dvtask.setStatusBarMessage("Analysing TLS version "+sh.protoVersion);
			if (sh.compression == 1) {
				compress = true;
				session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.DEFLATE_COMPRESSION, "true");
				logger.warn("Server vulnerable to CRIME attack.  Compression enabled.");
			}else{
				session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.DEFLATE_COMPRESSION, "false");
			}
		}

		dvtask.waitIfPaused();
		if (dvtask.isCancelled()) return null;
		dvtask.setStatusBarMessage("Sending TLS server Hello SSLv2");
		// Only probe SSLv2 if no protocol filter or if 0x0200 is in the filter
		ServerHelloSSLv2 sh2 = null;
		if (enabledProtocols == null || enabledProtocols.isEmpty()
				|| enabledProtocols.contains(0x0200)) {
			sh2 = connectV2(isa);
		}

		if (sh2 != null) {
			sv.add(0x0200);
		}

		if (sv.size() == 0) {
			dvtask.setStatusBarMessage("Server may not be SSL/TLS enabled. host=" + isa);
			logger.error("Server may not be SSL/TLS enabled. host=" + isa);
			return null;
		}

		dvtask.setStatusBarMessage("Normalizing cipher suite names to "+cipher_name_convention+" specification");
		
		Set<Integer> lastSuppCS = null;
		Map<Integer, Set<Integer>> suppCS = new TreeMap<Integer, Set<Integer>>();
		Set<String> certID = new TreeSet<String>();
		if (sh2 != null) {

			ArrayList<String> listv2 = new ArrayList<String>();
			String[] tmp = new String[0];

			Set<Integer> vc2 = new TreeSet<Integer>();
			for (int c : sh2.cipherSuites) {
				vc2.add(c);
			}
			for (int c : vc2) {

				String suitename = cipherSuiteStringV2(c, cipher_name_convention);
				listv2.add( suitename+"(0x"+Integer.toHexString(c)+")" );

			}

			suppCS.put(0x0200, vc2);
			if (sh2.serverCertName != null) {
				hostdata.setScalarValue("getServerMetadataInstance",sh2.serverCertHash, sh2.serverCertName);				
			}
			
			hostdata.setVectorValue( "getServerMetadataInstance",versionString(0x0200), listv2.toArray(tmp));
			
		}

		dvtask.waitIfPaused();
		if (dvtask.isCancelled()) return null;
		dvtask.setStatusBarMessage("Starting cipher suite analysis");

		for (int v : sv) {
			dvtask.waitIfPaused();
			if (dvtask.isCancelled()) return null;

			if (v == 0x0200) {
				continue;
			}
			Set<Integer> vsc = supportedSuites(isa, v, certID, dvtask);
			suppCS.put(v, vsc);

			ArrayList<String> listv = new ArrayList<String>();
			String[] tmp = new String[0];

			for (int c : vsc) {

				String suitename = cipherSuiteString(c, cipher_name_convention);
				listv.add( suitename+"(0x"+Integer.toHexString(c)+")" );
			}

			hostdata.setVectorValue( "getServerMetadataInstance",versionString(v), listv.toArray(tmp));

		}

		dvtask.setStatusBarMessage("Cipher suite analysis complete");
		
		return hostdata;
		
	}
	
	@SuppressWarnings("unchecked")
	private static void initCipherMap() {
		try (InputStream in = CipherSuiteUtil.class.getClassLoader()
				.getResourceAsStream("ciphermap.yaml")) {
			if (in == null) {
				throw new IllegalStateException("ciphermap.yaml not found on classpath");
			}
			Map<Integer, CipherSuite> parsed = parseCipherMapYaml(in);
			CIPHER_SUITES.clear();
			CIPHER_SUITES.putAll(parsed);
		} catch (IOException e) {
			logger.error("Failed to load ciphermap.yaml", e);
			throw new IllegalStateException("Failed to load ciphermap.yaml", e);
		}
		bCiphersInitialized = true;
	}

	@SuppressWarnings("unchecked")
	private static Map<Integer, CipherSuite> parseCipherMapYaml(InputStream is) {
		LoadSettings settings = LoadSettings.builder().build();
		Load load = new Load(settings);
		Map<String, Object> root = (Map<String, Object>) load.loadFromInputStream(is);
		List<Map<String, Object>> cipherSuites = (List<Map<String, Object>>) root.get("cipher_suites");
		if (cipherSuites == null) {
			throw new IllegalArgumentException("cipher_suites key not found in YAML");
		}

		Map<Integer, CipherSuite> result = new TreeMap<>();
		for (Map<String, Object> suiteObj : cipherSuites) {
			int suiteId = parseHexId((String) suiteObj.get("id"));
			int strength = mapStrength((String) suiteObj.get("strength"));
			Map<String, String> namesObj = (Map<String, String>) suiteObj.get("names");
			HashMap<String, String> names = new HashMap<>(namesObj);
			CipherSuite cs = new CipherSuite();
			cs.suite = suiteId;
			cs.names = names;
			cs.strength = strength;
			result.put(suiteId, cs);
		}
		return result;
	}

	/**
	 * Replace the cipher map with data from the given stream.
	 * The stream must contain valid cipher map YAML with a {@code cipher_suites} key.
	 * Internal state is only modified after the new data is fully parsed and validated.
	 *
	 * @param is InputStream containing cipher map YAML
	 * @throws IllegalArgumentException if the YAML is invalid or empty
	 */
	static synchronized void loadCipherMapFromStream(InputStream is) {
		Map<Integer, CipherSuite> parsed = parseCipherMapYaml(is);
		if (parsed.isEmpty()) {
			throw new IllegalArgumentException("Cipher map YAML contains no cipher suites");
		}
		CIPHER_SUITES.clear();
		CIPHER_SUITES.putAll(parsed);
		bCiphersInitialized = true;
	}

	/**
	 * Reset the cipher map to uninitialized state.
	 * The next operation that needs the cipher map will re-initialize from the classpath resource.
	 */
	static synchronized void resetCipherMap() {
		CIPHER_SUITES.clear();
		bCiphersInitialized = false;
	}

	static int parseHexId(String id) {
		String[] parts = id.split(",");
		if (parts.length == 2) {
			int hi = Integer.decode(parts[0].trim());
			int lo = Integer.decode(parts[1].trim());
			return (hi << 8) | lo;
		} else if (parts.length == 3) {
			int b0 = Integer.decode(parts[0].trim());
			int b1 = Integer.decode(parts[1].trim());
			int b2 = Integer.decode(parts[2].trim());
			return (b0 << 16) | (b1 << 8) | b2;
		}
		throw new IllegalArgumentException("Invalid cipher suite ID: " + id);
	}

	private static int mapStrength(String s) {
		return switch (s) {
			case "STRONG" -> STRONG;
			case "MEDIUM" -> MEDIUM;
			case "WEAK"   -> WEAK;
			case "CLEAR"  -> CLEAR;
			default       -> UNASSIGNED;
		};
	}


	/**
	 * Convert a TLS/SSL protocol version number to a human-readable string.
	 * @param version protocol version as a 16-bit integer (e.g., 0x0303 for TLS 1.2)
	 * @return human-readable version string (e.g., "TLSv1.2", "SSLv3")
	 */
	static String versionString(int version) {
		if (version == 0x0200) {
			return "SSLv2";
		} else if (version == 0x0300) {
			return "SSLv3";
		} else if ((version >>> 8) == 0x03) {
			return "TLSv1." + ((version & 0xFF) - 1);
		} else {
			return String.format("UNKNOWN_VERSION:0x%04X", version);
		}
	}
	
	/**
	 * Enumerate cipher suites supported by the server for a given protocol version.
	 * Repeatedly sends ClientHello messages, removing each server-selected suite until
	 * the server rejects all remaining candidates.
	 * @param isa server address to connect to
	 * @param version TLS/SSL protocol version to probe (e.g., 0x0303 for TLS 1.2)
	 * @param serverCertID set to which server certificate identifiers are added
	 * @param dvtask background task for cooperative cancellation, or null
	 * @return set of cipher suite IDs supported by the server
	 */
	static Set<Integer> supportedSuites(InetSocketAddress isa, int version,
		Set<String> serverCertID, BackgroundTask dvtask)
	{

		// Notes: the problem with using the past approach, CIPHER_SUITES.keySet(),
		// is that some servers use ciphers outside those included with the
		// Mozilla cipher mapings.  As a result DV was missing some ciphers.
		// The new approach is more comprensive but takes longer.
		//Set<Integer> cs = new TreeSet<Integer>(CIPHER_SUITES.keySet());

		Set<Integer> rs = new TreeSet<Integer>();

		// Exhaustively scan the IANA-assigned TLS 1.3 cipher suite range (0x1300-0x13FF).
		// This ensures future cipher suites are discovered even before ciphermap.json is updated.
		if (version >= 0x0304) {
			Set<Integer> tls13ciphers = new TreeSet<Integer>();
			for (int c = 0x1300; c <= 0x13FF; c++) {
				tls13ciphers.add(c);
			}
			for (;;) {
				if (dvtask != null) dvtask.waitIfPaused();
				if (dvtask != null && dvtask.isCancelled()) break;
				CipherSuiteUtilServerHello sh = connect(isa, version, tls13ciphers);
				if (sh == null) {
					break;
				}
				if (!tls13ciphers.contains(sh.cipherSuite)) {
					break;
				}
				tls13ciphers.remove(sh.cipherSuite);
				rs.add(sh.cipherSuite);
			}
			return rs;
		}

		int BLK_SIZE = 6000;
		int CIPHERMAPSZ = 0xFFFF;
		int i2=0; int i3=1;
		Set<Integer> scanblk = null;
		for ( int i=1; i<CIPHERMAPSZ; i+=BLK_SIZE ) {

			scanblk = new TreeSet<Integer>();
			while( i2< BLK_SIZE*i3 ) {
				scanblk.add(i2);
				i2++;
			}
			i3++;
			
//			// Take it easy on server, delay between a little between block checks
//			try {
//				Thread.currentThread().sleep((int)(Math.random()*750));
//			} catch (InterruptedException e) {}
			
			for (;;) {
				if (dvtask != null) dvtask.waitIfPaused();
				if (dvtask != null && dvtask.isCancelled()) break;
				//TODO could make this multi-threaded to speed up scanning.
				//  although need to be kind to servers.  Don't want too
				// many connections and create performance problems.
				CipherSuiteUtilServerHello sh = connect(isa, version, scanblk);
				if (sh == null) {
					break;
				}
				if (!scanblk.contains(sh.cipherSuite)) {
					//TODO need a better way to communicate this in the future
					String ciphersuite = Integer.toHexString(sh.cipherSuite);
					logger.warn("Server wants to use"
						+ " cipher suite "+ciphersuite+" which client"
						+ " did not announce.");
					break;
				}
				scanblk.remove(sh.cipherSuite);
				rs.add(sh.cipherSuite);
				if (sh.serverCertName != null) {
					serverCertID.add(sh.serverCertHash
						+ ": " + sh.serverCertName);
				}
			}
		
		}
		
		return rs;
	}

	
	/**
	 * Return the minimum encryption strength among the given cipher suites.
	 * @param supp set of cipher suite IDs to evaluate
	 * @return minimum strength constant (CLEAR, WEAK, MEDIUM, or STRONG)
	 */
	static int minStrength(Set<Integer> supp)
	{
		int m = STRONG;
		for (int suite : supp) {
			CipherSuite cs = CIPHER_SUITES.get(suite);
			if (cs == null) {
				continue;
			}
			if (cs.strength < m) {
				m = cs.strength;
			}
		}
		return m;
	}

	/**
	 * Return the maximum encryption strength among the given cipher suites.
	 * @param supp set of cipher suite IDs to evaluate
	 * @return maximum strength constant (CLEAR, WEAK, MEDIUM, or STRONG)
	 */
	static int maxStrength(Set<Integer> supp)
	{
		int m = CLEAR;
		for (int suite : supp) {
			CipherSuite cs = CIPHER_SUITES.get(suite);
			if (cs == null) {
				continue;
			}
			if (cs.strength > m) {
				m = cs.strength;
			}
		}
		return m;
	}
	
	/**
	 * Utility method to convert an <code>javax.security.cert.X509Certificate</code> to
	 * <code>java.security.cert.X509Certificate</code>.  No doubt, a bit of legacy.
	 * @param cert X509 certificate to convert.
	 * @return java.security.cert.X509Certificate Converted object
	 * @see http://exampledepot.8waytrips.com/egs/javax.security.cert/ConvertCert.html
	 */
//	public static java.security.cert.X509Certificate convert(javax.security.cert.X509Certificate cert) {
//	    try {
//	        byte[] encoded = cert.getEncoded();
//	        ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
//	        java.security.cert.CertificateFactory cf
//	            = java.security.cert.CertificateFactory.getInstance("X.509");
//	        return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
//	    } catch (javax.security.cert.CertificateEncodingException e) {
//			logger.error(e.getMessage(),e);
//	    } catch (java.security.cert.CertificateException e) {
//			logger.error(e.getMessage(),e);
//	    }
//	    return null;
//	}
	
	/**
	 * Analysis to determine cipher suite strength.
	 * @param protocol Cipher suite protocol to test.
	 * @return String indicating strength, CLEAR(no encryption), WEAK, MEDIUM, STRONG. 
	 */
	static final String getStrength(String protocol) {
		
		String clear = "CLEAR{no encryption}";
		String weak = "WEAK";
		String medium = "MEDIUM";
		String strong = "STRONG";
		String unknown = "UNKNOWN";
		
		String result = unknown;
		
		if (protocol.contains("_NULL_") ) {
			
			result = clear;
		
		} else {
			
			Collection suites = CIPHER_SUITES.values();
			CipherSuite c = null;
			Iterator i = suites.iterator();
			while( i.hasNext() ) {
				c = (CipherSuite)i.next();
				if ( c.names.containsValue(protocol) ) {
					switch ( c.strength ) {
					case STRONG:
						result = strong;
						break;
					case MEDIUM:
						result = medium;
						break;
					case WEAK:
						result = weak;
						break;
					}
				}

			}
			
		}
	    
		return result;
		
	}
	
	/**
	 * Retrieve a server certificate based upon URL.
	 * @param url Target URL
	 * @return X509Certificate Server certificate.
	 * @throws Exception Thrown on problems.
	 */
	static final X509Certificate getServerCertificate(URL url) throws Exception {
		
		X509Certificate[] certs = getServerCertificateChain(url);
		
		return certs[0];
		
	}
	
	/**
	 * Return server responses
	 * @param url Target URL
	 * @return Map HTTPS response headers
	 * @throws Exception Thrown on problems.
	 */
	static final Map<String, List<String>> getHttpResponseHeaders(URL url) throws Exception {

		synchronized (TLS_CHAIN_TESTING_LOCK) {
			HttpsURLConnection conn = null;

			Map<String, List<String>> result = new HashMap<String, List<String>>();

			try {

				enableTLSChainTesting(false);

				conn = (HttpsURLConnection)url.openConnection();
				conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
				conn.setReadTimeout(READ_TIMEOUT_MS);

				conn.connect();

				result = conn.getHeaderFields();

			} finally {

				if (conn != null) conn.disconnect();
				enableTLSChainTesting(true);
			}

			return result;
		}

	}

	/**
	 * Enable default testing for TLS certificate trust chains.
	 * @param value true, chain will be tested.  false, chain will not be tested.
	 * @throws Exception Thrown on error
	 */
	static final void enableTLSChainTesting( boolean value ) throws Exception {

		if( value ) {
			
			HttpsURLConnection.setDefaultSSLSocketFactory(dsc);
			HttpsURLConnection.setDefaultHostnameVerifier(dhv);
			
		} else {
			
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, new TrustManager[] { new TrustAllX509TrustManager() }, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			HttpsURLConnection.setDefaultHostnameVerifier( new HostnameVerifier(){
			    public boolean verify(String string,SSLSession ssls) {
			        return true;
			    }
			});
			
		}
		
	}
	
	/**
	 * Retrieve a certificate chain based upon URL.  Note this API will return
	 * certificates with unvalidated and possibly bad trust chains.
	 * @param url Target URL
	 * @return X509Certificate Certificate chain
	 * @throws Exception Thrown on problems.
	 * @see <a href="http://stackoverflow.com/questions/19723415/java-overriding-function-to-disable-ssl-certificate-check">java-overriding-function-to-disable-ssl-certificate-check</a>
	 */
	static final X509Certificate[] getServerCertificateChain(URL url) throws Exception {

		synchronized (TLS_CHAIN_TESTING_LOCK) {
			ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
			HttpsURLConnection conn = null;

			try {

				enableTLSChainTesting(false);

				conn = (HttpsURLConnection)url.openConnection();
				conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
				conn.setReadTimeout(READ_TIMEOUT_MS);
				conn.connect();
				Certificate[] certs = conn.getServerCertificates();

				for (Certificate cert : certs) {

					if(cert instanceof X509Certificate) {
						list.add( (X509Certificate)cert );
					} else {
						logger.info("Unsupported certificate type.  type="+cert.getClass().getName());
					}
				}

			} finally {

				if (conn != null) conn.disconnect();
				enableTLSChainTesting(true);

			}

			return list.toArray(new X509Certificate[0]);
		}
	}
	
	/**
	 * Get a list of the Java root certificates.  
	 * For more information, <a href="http://stackoverflow.com/questions/3508050/how-can-i-get-a-list-of-trusted-root-certificates-in-java">How can I get a list of trusted root certificates in Java?</a>
	 * @return An array of X509Certificates root certificates from the Java trust store
	 * @throws Exception Thrown on problems.
	 */
	static final X509Certificate[] getJavaRootCertificates() throws Exception {

		//TODO: Maybe be good to consider caching this at some point (at least for a few seconds)

		// Load the JDK's cacerts keystore file
		String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
    	logger.debug("CACERTS file, "+filename);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		String password = "changeit"; //default password
		try (FileInputStream is = new FileInputStream(filename)) {
			keystore.load(is, password.toCharArray());
		}
		
		// This class retrieves the most-trusted CAs from the keystore
		PKIXParameters params = new PKIXParameters(keystore);
		
		// Get the set of trust anchors, which contain the most-trusted CA certificates,
		// and return the java root certs.
		Iterator<TrustAnchor> it = params.getTrustAnchors().iterator();
		ArrayList<X509Certificate> result = new ArrayList<X509Certificate>();
		while( it.hasNext() ) {
			TrustAnchor ta = it.next();
			result.add(ta.getTrustedCert());
		}
		
		return result.toArray(new X509Certificate[0]);

	}

//	/**
//	 * Test to see if a particular SHA1 hash is a root in the Java system keystore.
//	 * @param sha1hash
//	 * @return true, SHA1 hash belongs to a Java root.  false, no Java root found.
//	 */
//	public static final boolean isJavaRootCertificateSHA1(String sha1hash) throws Exception {
//		
//		boolean result = false;
//		
//		for( X509Certificate cert : getJavaRootCertificates() ) {
//			
//			String fingerprint = sha1Fingerprint(cert.getEncoded());
//		
//			if( fingerprint.equals(sha1hash) ) {
//				
//				result = true; break;
//			}
//		}
//		
//		return result;
//	}
	
	/**
	 * Test to see if a particular IssuerDN is a root in the Java system keystore.
	 * @param IssuerDN Issuing authority
	 * @return true, IssuerDN matches a Java root.  false, no matching IssuerDN found.
	 */
	static final boolean isJavaRootCertificateDN(String IssuerDN) throws Exception {
		
		boolean result = false;
		
		for( X509Certificate cert : getJavaRootCertificates() ) {
			
			if ( cert.getIssuerX500Principal().getName().equals(IssuerDN) ) {
				
				result = true; break;
			}
		}
		
		return result;
	}
	
	/**
	 * Check trust status of each certificate in the chain.
	 * @param certs Chain of X509Certificates to test.
	 * @param url Server URL to test against.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws UnknownHostException
	 * @throws IOException
	 * @return True, the certificate chain is trusted.  False, the chain is not trusted.
	 */
	static final boolean checkTrustedCertificate( X509Certificate[] certs, URL url) throws KeyStoreException,
			NoSuchAlgorithmException, UnknownHostException, IOException {

		boolean valid = false;

		int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = null;
        SSLSession session;
        try {
            Socket rawSocket = new Socket();
            rawSocket.connect(new InetSocketAddress(url.getHost(), port), CONNECT_TIMEOUT_MS);
            socket = (SSLSocket) factory.createSocket(rawSocket, url.getHost(), port, true);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            socket.startHandshake();
            session = socket.getSession();
        } catch (javax.net.ssl.SSLHandshakeException e) {
            // JSSE handshake failed (expired cert, self-signed, untrusted CA, etc.)
            // This means the certificate is NOT trusted — return false.
            logger.debug("JSSE handshake failed for trust check (expected for bad certs): {}", e.getMessage());
            if (socket != null) try { socket.close(); } catch (IOException ignored) {}
            return false;
        }

        // Extract JSSE-negotiated chain for comparison with trust-disabled chain
        X509Certificate[] jsseChain = null;
        try {
            jsseChain = (X509Certificate[]) session.getPeerCertificates();
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            logger.warn("Could not retrieve JSSE peer certificates for {}", url);
        }

        // Compare trust-disabled chain against JSSE-negotiated chain
        if (jsseChain != null && certs != null) {
            if (certs.length != jsseChain.length) {
                logger.warn("Chain length mismatch for {}: trust-disabled={} vs JSSE={}",
                    url, certs.length, jsseChain.length);
            } else {
                for (int i = 0; i < certs.length; i++) {
                    try {
                        if (!certFingerprint(certs[i]).equals(certFingerprint(jsseChain[i]))) {
                            logger.warn("Chain cert [{}] mismatch for {}: {} vs {}", i, url,
                                certs[i].getSubjectX500Principal(), jsseChain[i].getSubjectX500Principal());
                        }
                    } catch (CertificateException e) {
                        logger.warn("Could not compute fingerprint for chain comparison at index {}", i);
                    }
                }
            }
        }

        String keyexchalgo = getKeyExchangeAlgorithm(session, certs);
		try { socket.close(); } catch( IOException e ) {}

		TrustManagerFactory trustManagerFactory =
			    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init((KeyStore)null);
			// you could use a non-default KeyStore as your truststore too, instead of null.

			for (TrustManager trustManager: trustManagerFactory.getTrustManagers()) {
			    if (trustManager instanceof X509TrustManager) {
			        X509TrustManager x509TrustManager = (X509TrustManager)trustManager;
			        try {
			        	x509TrustManager.checkServerTrusted(certs,keyexchalgo);
			        	valid = true;
			        } catch( CertificateException e ) {
			        	// Eat the stacktrace
			        	logger.error( "url="+url.toString() );
			        }
			    }

			}
		return valid;
	}

	/**
	 * Compute SHA-256 fingerprint of a certificate for chain comparison.
	 */
	private static String certFingerprint(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			return Base64.getEncoder().encodeToString(md.digest(cert.getEncoded()));
		} catch (java.security.cert.CertificateEncodingException e) {
			throw new CertificateException("Failed to encode certificate", e);
		}
	}
	
	// check OCSP
//	public static final String checkOCSPStatus(X509Certificate cert, X509Certificate issuer) {
//		
//		// init PKIX parameters
//        PKIXParameters params = null;
//	    params = new PKIXParameters(trustedCertsSet);
//	    params.addCertStore(store);
//	
//	    // enable OCSP
//	    Security.setProperty("ocsp.enable", "true");
//	    if (ocspServer != null) {
//			Security.setProperty("ocsp.responderURL", args[1]);
//			Security.setProperty("ocsp.responderCertSubjectName",
//			    ocspCert.getSubjectX500Principal().getName());
//	    }
//	
//	    // perform validation
//	    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
//	    PKIXCertPathValidatorResult cpv_result  =
//		(PKIXCertPathValidatorResult) cpv.validate(cp, params);
//	    X509Certificate trustedCert = (X509Certificate)
//		cpv_result.getTrustAnchor().getTrustedCert();
//	
//	    if (trustedCert == null) {
//	    	System.out.println("Trsuted Cert = NULL");
//	    } else {
//	    	System.out.println("Trusted CA DN = " +
//	    			trustedCert.getSubjectDN());
//	    }
//		
//		return buff.toString();	
//		
//    }
	
	/**
	 * Parse out the Cipher's Key Exchange Algorithm.
	 * For TLS 1.3 cipher suites (which don't contain "_WITH"), the auth type
	 * is derived from the end-entity certificate's public key type.
	 * @param session Target SSLSession
	 * @param certs Certificate chain (used for TLS 1.3 auth type derivation)
	 * @return String TLS key exchange algorithm suitable for X509TrustManager.checkServerTrusted()
	 */
	private static final String getKeyExchangeAlgorithm( SSLSession session, X509Certificate[] certs ) {

		String cipher = session.getCipherSuite().toString();

		int i1 = cipher.indexOf('_')+1;
		int i2 = cipher.indexOf("_WITH");

		// TLS 1.3 cipher suites (e.g., TLS_AES_128_GCM_SHA256) don't include
		// the key exchange algorithm in the name - it's negotiated separately.
		// Derive the auth type from the end-entity certificate's public key.
		if (i2 == -1) {
			if (certs != null && certs.length > 0) {
				PublicKey pk = certs[0].getPublicKey();
				if (pk instanceof ECPublicKey) return "ECDHE_ECDSA";
				if (pk instanceof RSAPublicKey) return "ECDHE_RSA";
			}
			return "UNKNOWN";
		}

		String keyexch = cipher.substring(i1, i2);

		return keyexch;

	}
	
	/**
	 * Is this test certificate a self-signed certificate.
	 * @param cert Target certificate to test.
	 * @return boolean True, certificate is self-signed.  False, certificate is not self-signed. 
	 */
	static final boolean isSelfSignedCertificate( X509Certificate cert ) {
		
		boolean result = false;
		
		if (cert != null ) {
			
			if ( cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal()) )
				result = true;
			
		}
		
			return result;
		
		}
	
	   /**
	    * Generate signer fingerprint from certificate bytes
	    * @param der Certificate in bytes
	    * @param signatureAlgorithm Signing algorithm for the certificate, ex: SHA256
	    * @return String Signer fingerprint in hex.
	    * @throws NoSuchAlgorithmException
	    */
	   public static final String signerFingerprint( byte[] der, String signatureAlgorithm ) throws NoSuchAlgorithmException {

		   MessageDigest sha1 = MessageDigest.getInstance(signatureAlgorithm);
		   sha1.update( der );

		   StringBuilder buff = new StringBuilder();
		   buff.append(byteArrayToHex(sha1.digest()));

		   return buff.toString();

	   }	
	
//	   /**
//	    * Generate SHA1 fingerprint from certificate bytes
//	    * @param der Certificate in bytes
//	    * @return String SHA1 fingerprint in hex.
//	    * @throws NoSuchAlgorithmException
//	    */
//	   static final String sha1Fingerprint( byte[] der ) throws NoSuchAlgorithmException {
//		   
//		   MessageDigest sha1 = MessageDigest.getInstance("SHA1");
//		   sha1.update( der );
//		   
//		   StringBuffer buff = new StringBuffer();
//		   buff.append(byteArrayToHex(sha1.digest()));
//		   
//		   return buff.toString();
//		   
//	   }
	   
//	   /**
//	    * Generate MD5 fingerprint from certificate bytes
//	    * @param der Certificate in bytes
//	    * @return String MD5 fingerprint in hex.
//	    * @throws NoSuchAlgorithmException
//	    */	   
//	   static final String md5Fingerprint( byte[] der ) throws NoSuchAlgorithmException {
//		   
//		   MessageDigest sha1 = MessageDigest.getInstance("MD5");
//		   sha1.update( der );
//		   
//		   StringBuffer buff = new StringBuffer();
//		   buff.append(byteArrayToHex(sha1.digest()));
//		   
//		   return buff.toString();
//		   
//	   }
	   
	   /**
	    * Convert an array of bytes to a String based hex representation
	    * @param a Target byte array to convert.
	    * @return String String based hex representation of target byte array. 
	    */
	   static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a) {
		      sb.append(String.format("%02x", b & 0xff));
		      sb.append(':');
		   }
		   sb.setLength(sb.length()-1);
		   return sb.toString().toUpperCase();
		}

	   /**
	    * Returns human readable OID name for the OID number.
	    * @param oidkey OID number sequence.  Ex: 2.5.29.15
	    * @return  Human readable String representation of the OID number sequence.  Ex: keyusage
	    */
	   static String getOIDKeyName(String oidkey) {

		   // TODO: Need to figure out a better way to do this.
		   return (OIDMAP.get(oidkey)!=null) ? OIDMAP.get(oidkey) : oidkey;
		   
	   }

	/**
	 * Convert <code>der</code> encoded data to <code>DerParser.DerValue</code>.
	 * For more information,
	 * (<a href="http://stackoverflow.com/questions/2409618/how-do-i-decode-a-der-encoded-string-in-java">StackOverflow: How do I decode a DER encoded string in Java?</a>)
	 * @param data byte[] of <code>der</code> encoded data
	 * @return <code>DerParser.DerValue</code> representation of <code>der</code> encoded data
	 * @throws IOException
	 */
	static final DerParser.DerValue toDERObject(byte[] data) throws IOException {
		return DerParser.parse(data);
	}

		/**
	 * Reentrant method to decode DerValues. Types handled: OCTET STRING,
	 * SEQUENCE, OBJECT IDENTIFIER, IA5String, UTF8String, VisibleString,
	 * PrintableString, BIT STRING, BOOLEAN, INTEGER, SET, and context-specific
	 * tagged objects.
	 * @param derValue The DER value to process
	 * @param buff StringBuilder to append results to
	 * @throws IOException
	 */
	static final void walkASN1Sequence( DerParser.DerValue derValue, StringBuilder buff ) throws IOException {
		int tag = derValue.getTag();

		// OCTET STRING
		if (tag == DerParser.TAG_OCTET_STRING) {
			byte[] bytes = derValue.getOctetString();
			try {
				DerParser.DerValue inner = DerParser.parse(bytes);
				walkASN1Sequence(inner, buff);
			} catch (IOException e) {
				buff.append(byteArrayToHex(bytes));
			}

		// SEQUENCE or SET (constructed)
		} else if (tag == DerParser.TAG_SEQUENCE || tag == DerParser.TAG_SET || derValue.isConstructed()) {
			List<DerParser.DerValue> elements;
			if (tag == DerParser.TAG_SET) {
				elements = derValue.getSet();
			} else {
				elements = derValue.getSequence();
			}
			for (DerParser.DerValue element : elements) {
				walkASN1Sequence(element, buff);
			}

		// OBJECT IDENTIFIER
		} else if (tag == DerParser.TAG_OBJECT_IDENTIFIER) {
			String oid = derValue.getObjectIdentifier();
			String kn = CipherSuiteUtil.getOIDKeyName(oid);

			if (kn.equals("2.5.29.37.0")) {
				buff.append("anyextendedkeyusage ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.1")) {
				buff.append("serverauth ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.2")) {
				buff.append("clientauth ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.3")) {
				buff.append("codesigning ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.4")) {
				buff.append("emailprotection ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.8")) {
				buff.append("timestamping ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.9")) {
				buff.append("ocspsigner ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.15")) {
				buff.append("scvpserver ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.16")) {
				buff.append("scvpclient ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.22")) {
				buff.append("eku_pkix_sshserver ");
			} else if (kn.equals("1.3.6.1.5.5.7.3.21")) {
				buff.append("eku_pkix_sshclient ");
			} else {
				buff.append(CipherSuiteUtil.getOIDKeyName(oid));
				buff.append("=");
			}

		// VisibleString
		} else if (tag == DerParser.TAG_VISIBLE_STRING) {
			buff.append(derValue.getVisibleString());

		// IA5String
		} else if (tag == DerParser.TAG_IA5_STRING) {
			buff.append(derValue.getIA5String());

		// UTF8String
		} else if (tag == DerParser.TAG_UTF8_STRING) {
			buff.append(derValue.getUTF8String());

		// PrintableString
		} else if (tag == DerParser.TAG_PRINTABLE_STRING) {
			buff.append(derValue.getPrintableString());

		// BIT STRING (KeyUsage)
		// X.509 KeyUsage bits are numbered from MSB: bit 0 = 0x80, bit 1 = 0x40, etc.
		} else if (tag == DerParser.TAG_BIT_STRING) {
			byte[] bits = derValue.getBitString();
			int byte0 = (bits.length > 0) ? (bits[0] & 0xFF) : 0;
			int byte1 = (bits.length > 1) ? (bits[1] & 0xFF) : 0;

			// Bit 0 (MSB of byte 0) = digitalSignature
			if ((byte0 & 0x80) != 0)
				buff.append("digitalSignature ");
			// Bit 1 = nonRepudiation (aka contentCommitment)
			if ((byte0 & 0x40) != 0)
				buff.append("nonRepudiation ");
			// Bit 2 = keyEncipherment
			if ((byte0 & 0x20) != 0)
				buff.append("keyEncipherment ");
			// Bit 3 = dataEncipherment
			if ((byte0 & 0x10) != 0)
				buff.append("dataEncipherment ");
			// Bit 4 = keyAgreement
			if ((byte0 & 0x08) != 0)
				buff.append("keyAgreement ");
			// Bit 5 = keyCertSign
			if ((byte0 & 0x04) != 0)
				buff.append("keyCertSign ");
			// Bit 6 = cRLSign
			if ((byte0 & 0x02) != 0)
				buff.append("cRLSign ");
			// Bit 7 = encipherOnly
			if ((byte0 & 0x01) != 0)
				buff.append("encipherOnly ");
			// Bit 8 (MSB of byte 1) = decipherOnly
			if ((byte1 & 0x80) != 0)
				buff.append("decipherOnly ");

		// BOOLEAN
		} else if (tag == DerParser.TAG_BOOLEAN) {
			buff.append(derValue.getBoolean() ? "TRUE" : "FALSE");

		// INTEGER
		} else if (tag == DerParser.TAG_INTEGER) {
			buff.append(derValue.getInteger().toString());

		// ENUMERATED
		} else if (tag == DerParser.TAG_ENUMERATED) {
			buff.append(derValue.getEnumValue());

		// NULL - just skip it, nothing to output
		} else if (tag == DerParser.TAG_NULL) {
			// NULL has no content, skip

		// Context-specific tagged objects
		} else if (derValue.isContextSpecific()) {
			int tagNo = derValue.getContextTag();
			byte[] rawValue = derValue.getValue();

			if (tagNo == 6) { // URI
				buff.append(new String(rawValue, java.nio.charset.StandardCharsets.UTF_8));
				buff.append(" | ");
			} else if (tagNo == 2) { // SubjectAlternativeName (dNSName)
				buff.append(new String(rawValue, java.nio.charset.StandardCharsets.UTF_8));
				buff.append(" | ");
			} else if (tagNo == 1 || tagNo == 0 || tagNo == 4) {
				// NameConstraints, CRLDistributionPoints, AuthorityKeyIdentifier
				if (derValue.isConstructed()) {
					List<DerParser.DerValue> elements = derValue.getTaggedSequence();
					for (DerParser.DerValue element : elements) {
						walkASN1Sequence(element, buff);
					}
				} else {
					try {
						DerParser.DerValue inner = DerParser.parse(rawValue);
						walkASN1Sequence(inner, buff);
					} catch (IOException e) {
						buff.append(byteArrayToHex(rawValue));
					}
				}
			} else {
				StringBuilder buff2 = new StringBuilder();
				buff2.append("type=").append(tagNo).append(" ");
				String hex = CipherSuiteUtil.byteArrayToHex(rawValue);
				buff2.append(hex);
				buff2.append(" | ");
				buff.append(buff2.toString());
				logger.info("Unhandled ASN1TaggedObject type. RAW=" + buff2.toString());
			}

		} else {
			buff.append("Unhandled type, see log");
			buff.append(" | ");
			logger.error("Unhandled primitive data type, tag=0x" + Integer.toHexString(tag));
		}
	}

	/**
	 * Return the value of the OID associated with the X509Certificate.  For more information,
	 * <a href="http://stackoverflow.com/questions/2409618/how-do-i-decode-a-der-encoded-string-in-java">How do I decode a DER encoded string in Java?</a>
	 * @param X509Certificate Certificate to test.
	 * @param oid OID to retrieve.
	 * @return String String value for the specified OID parameter. 
	 * @throws IOException
	 */
	static final String getExtensionValue(X509Certificate X509Certificate, String oid) throws IOException {

		StringBuilder buff = new StringBuilder();

		buff.append('[');
		
	    byte[] extensionValue = X509Certificate.getExtensionValue(oid);
	
	    if (extensionValue == null)  return null;
	    	
	    walkASN1Sequence( toDERObject(extensionValue), buff);
	    
	    if( buff.toString().endsWith(" | ")) {
	    	buff.setLength(buff.length()-3);
	    
	    } else if( buff.toString().endsWith("| ")) {
	    	buff.setLength(buff.length()-2);
	    
	    } else if( buff.toString().endsWith(" ")) {
	    	buff.setLength(buff.length()-1);
	    }
		
	    buff.append(']');
	
	    return buff.toString();
	
	}
	   

	/**
	 * Connect to the server using {@link TlsSocket} and return handshake metadata.
	 * This is the preferred connection method for new code.
	 * @param isa server address and port
	 * @param version TLS protocol version to advertise
	 * @param cipherSuites cipher suite IDs to offer in the ClientHello
	 * @param hostname SNI hostname for the TLS handshake
	 * @return handshake metadata, or null if the connection failed
	 */
	static TlsMetadata connectDVTls(InetSocketAddress isa, int version,
			Collection<Integer> cipherSuites, String hostname) {
		try {
			ClientHelloConfig config = new ClientHelloConfig()
					.setTlsVersion(version)
					.setCipherSuites(new ArrayList<>(cipherSuites))
					.setIncludeStatusRequest(true);

			if (version >= 0x0304) {
				config.setIncludeKeyShare(true)
					  .setSupportedVersions(Arrays.asList(version, 0x0303, 0x0302, 0x0301));
			} else {
				config.setSupportedVersions(Arrays.asList(version));
			}

			TlsSocket socket = new TlsSocket(hostname, isa.getPort());
			socket.setClientHelloConfig(config);
			socket.setConnectTimeoutMs(5000);
			socket.setReadTimeoutMs(10000);

			try {
				TlsMetadata metadata = socket.performHandshake();
				if (metadata.isConnectionSucceeded()) {
					return metadata;
				}
			} finally {
				socket.close();
			}
		} catch (Exception e) {
			// Connection failed
			logger.debug("TlsSocket connection failed: {}", e.getMessage());
		}
		return null;
	}

	/**
	 * Send a ClientHello and decode the ServerHello response, using the host from the address for SNI.
	 * @param isa server address
	 * @param version TLS/SSL version to advertise
	 * @param cipherSuites cipher suite IDs to offer
	 * @return parsed ServerHello, or null on error
	 */
	static CipherSuiteUtilServerHello connect(InetSocketAddress isa,
		int version, Collection<Integer> cipherSuites)
	{
		return connect(isa, version, cipherSuites, isa.getHostName());
	}

	/**
	 * Send a ClientHello with the specified SNI hostname and decode the ServerHello response.
	 * @param isa server address
	 * @param version TLS/SSL version to advertise
	 * @param cipherSuites cipher suite IDs to offer
	 * @param hostname SNI hostname to include in the ClientHello extension
	 * @return parsed ServerHello, or null on error
	 */
	static CipherSuiteUtilServerHello connect(InetSocketAddress isa,
		int version, Collection<Integer> cipherSuites, String hostname)
	{
		Socket s = null;
		try {
			s = new Socket();
			try {
				s.connect(isa, CONNECT_TIMEOUT_MS);
				s.setSoTimeout(READ_TIMEOUT_MS);
			} catch (IOException ioe) {
				logger.error("could not connect to "
					+ isa + ": " + ioe.toString());
				return null;
			}
			// For TLS 1.3, still advertise TLS 1.2 in the record layer
			int recordVersion = (version >= 0x0304) ? 0x0303 : version;
			byte[] ch = makeClientHello(version, cipherSuites, hostname);
			OutputRecord orec = new OutputRecord(
				s.getOutputStream());
			orec.setType(HANDSHAKE);
			orec.setVersion(recordVersion);
			orec.write(ch);
			orec.flush();
			return new CipherSuiteUtilServerHello(s.getInputStream());
		} catch (IOException ioe) {
			// ignored
		} finally {
			try {
				s.close();
			} catch (IOException ioe) {
				// ignored
			}
		}
		return null;
	}
	
	/**
	 * Send an SSLv2 CLIENT HELLO and decode the SSLv2 SERVER HELLO response.
	 * @param isa server address
	 * @return parsed SSLv2 ServerHello, or null on error
	 */
	static ServerHelloSSLv2 connectV2(InetSocketAddress isa)
	{
		Socket s = null;
		try {
			s = new Socket();
			try {
				s.connect(isa, CONNECT_TIMEOUT_MS);
				s.setSoTimeout(READ_TIMEOUT_MS);
			} catch (IOException ioe) {
				logger.error("could not connect to "
					+ isa + ": " + ioe.toString());
				return null;
			}
			s.getOutputStream().write(SSL2_CLIENT_HELLO);
			return new ServerHelloSSLv2(s.getInputStream());
		} catch (IOException ioe) {
			// ignored
		} finally {
			try {
				s.close();
			} catch (IOException ioe) {
				// ignored
			}
		}
		return null;
	}
	
	/**
	 * Read exactly {@code buf.length} bytes from the input stream into the buffer.
	 * @param in input stream to read from
	 * @param buf destination buffer
	 * @throws IOException if the stream ends before the buffer is filled
	 */
	static void readFully(InputStream in, byte[] buf)
			throws IOException
		{
			readFully(in, buf, 0, buf.length);
		}

	/**
	 * Read exactly {@code len} bytes from the input stream into the buffer at the given offset.
	 * @param in input stream to read from
	 * @param buf destination buffer
	 * @param off offset in the buffer to start writing
	 * @param len number of bytes to read
	 * @throws IOException if the stream ends before all bytes are read
	 */
	static void readFully(InputStream in, byte[] buf, int off, int len)
		throws IOException
	{
		while (len > 0) {
			int rlen = in.read(buf, off, len);
			if (rlen < 0) {
				throw new EOFException();
			}
			off += rlen;
			len -= rlen;
		}
	}
	
	/*
	 * A custom stream which encodes data bytes into SSL/TLS records
	 * (no encryption).
	 */
	static class OutputRecord extends OutputStream {

		private OutputStream out;
		private byte[] buffer = new byte[MAX_RECORD_LEN + 5];
		private int ptr;
		private int version;
		private int type;

		OutputRecord(OutputStream out)
		{
			this.out = out;
			ptr = 5;
		}

		void setType(int type)
		{
			this.type = type;
		}

		void setVersion(int version)
		{
			this.version = version;
		}

		public void flush()
			throws IOException
		{
			buffer[0] = (byte)type;
			enc16be(version, buffer, 1);
			enc16be(ptr - 5, buffer, 3);
			out.write(buffer, 0, ptr);
			out.flush();
			ptr = 5;
		}

		public void write(int b)
			throws IOException
		{
			buffer[ptr ++] = (byte)b;
			if (ptr == buffer.length) {
				flush();
			}
		}

		public void write(byte[] buf, int off, int len)
			throws IOException
		{
			while (len > 0) {
				int clen = Math.min(buffer.length - ptr, len);
				System.arraycopy(buf, off, buffer, ptr, clen);
				ptr += clen;
				off += clen;
				len -= clen;
				if (ptr == buffer.length) {
					flush();
				}
			}
		}
	}

	
	/** Encode a 16-bit value in big-endian order into a byte array. */
	static final void enc16be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >>> 8);
		buf[off + 1] = (byte)val;
	}

	/** Encode a 16-bit value in big-endian order to an output stream. */
	static final void enc16be(int val, ByteArrayOutputStream out)
	{
		out.write(val >>> 8);
		out.write(val);
	}

	/** Encode a 24-bit value in big-endian order into a byte array. */
	static final void enc24be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >>> 16);
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)val;
	}

	/** Encode a 32-bit value in big-endian order into a byte array. */
	static final void enc32be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >>> 24);
		buf[off + 1] = (byte)(val >>> 16);
		buf[off + 2] = (byte)(val >>> 8);
		buf[off + 3] = (byte)val;
	}

	/** Decode a 16-bit big-endian value from a byte array. */
	static final int dec16be(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 8)
			| (buf[off + 1] & 0xFF);
	}

	/** Decode a 24-bit big-endian value from a byte array. */
	static final int dec24be(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 16)
			| ((buf[off + 1] & 0xFF) << 8)
			| (buf[off + 2] & 0xFF);
	}

	/** Decode a 32-bit big-endian value from a byte array. */
	static final int dec32be(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 24)
			| ((buf[off + 1] & 0xFF) << 16)
			| ((buf[off + 2] & 0xFF) << 8)
			| (buf[off + 3] & 0xFF);
	}

	/**
	 * Compute the SHA-1 hash of a byte array and return it as a lowercase hex string.
	 * @param buf bytes to hash
	 * @return SHA-1 hash in hexadecimal
	 */
	static String doSHA1(byte[] buf)
	{
		return doSHA1(buf, 0, buf.length);
	}

	/**
	 * Compute the SHA-1 hash of a byte range and return it as a lowercase hex string.
	 * @param buf source byte array
	 * @param off starting offset
	 * @param len number of bytes to hash
	 * @return SHA-1 hash in hexadecimal
	 */
	static String doSHA1(byte[] buf, int off, int len)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(buf, off, len);
			byte[] hv = md.digest();
			Formatter f = new Formatter();
			for (byte b : hv) {
				f.format("%02x", b & 0xFF);
			}
			return f.toString();
		} catch (NoSuchAlgorithmException nsae) {
			throw new Error(nsae);
		}
	}
	
	/**
	 * Build a TLS ClientHello message with the specified version, cipher suites, and SNI hostname.
	 * @param version maximum TLS version to advertise
	 * @param cipherSuites cipher suite IDs to include
	 * @param hostname SNI hostname (may be null to omit the extension)
	 * @return encoded ClientHello message bytes
	 */
	static byte[] makeClientHello(int version,
		Collection<Integer> cipherSuites, String hostname)
	{
		try {
			return makeClientHello0(version, cipherSuites, hostname);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}
	}

	/**
	 * Internal implementation that assembles the raw ClientHello byte sequence.
	 * Includes SNI, supported_versions, signature_algorithms, supported_groups,
	 * key_share (TLS 1.3), and ec_point_formats extensions.
	 * @param version maximum TLS version to advertise
	 * @param cipherSuites cipher suite IDs to include
	 * @param hostname SNI hostname (may be null)
	 * @return encoded ClientHello message bytes
	 * @throws IOException on stream write errors
	 */
	static byte[] makeClientHello0(int version,
		Collection<Integer> cipherSuites, String hostname)
		throws IOException
	{
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		/*
		 * Message header:
		 *   message type: one byte (1 = "ClientHello")
		 *   message length: three bytes (this will be adjusted
		 *   at the end of this method).
		 */
		b.write(1);
		b.write(0);
		b.write(0);
		b.write(0);

		/*
		 * The maximum version that we intend to support.
		 * For TLS 1.3, we still use 0x0303 (TLS 1.2) here
		 * and indicate TLS 1.3 via supported_versions extension.
		 */
		int legacyVersion = (version >= 0x0304) ? 0x0303 : version;
		b.write(legacyVersion >>> 8);
		b.write(legacyVersion);

		/*
		 * The client random has length 32 bytes, but begins with
		 * the client's notion of the current time, over 32 bits
		 * (seconds since 1970/01/01 00:00:00 UTC, not counting
		 * leap seconds).
		 */
		byte[] rand = new byte[32];
		RNG.nextBytes(rand);
		enc32be((int)(System.currentTimeMillis() / 1000), rand, 0);
		b.write(rand);

		/*
		 * We send an empty session ID.
		 */
		b.write(0);

		/*
		 * The list of cipher suites (list of 16-bit values; the
		 * list length in bytes is written first).
		 */
		int num = cipherSuites.size();
		byte[] cs = new byte[2 + num * 2];
		enc16be(num * 2, cs, 0);
		int j = 2;
		for (int s : cipherSuites) {
			enc16be(s, cs, j);
			j += 2;
		}
		b.write(cs);

		/*
		 * Compression methods: for TLS 1.3 (RFC 8446), MUST be exactly
		 * one byte set to 0x00. For older versions, we also claim
		 * to support Deflate (1) for CRIME attack detection.
		 */
		if (version >= 0x0304) {
			b.write(1);  // 1 compression method
			b.write(0);  // null compression only (TLS 1.3 requirement)
		} else {
			b.write(2);
			b.write(1);
			b.write(0);
		}

		/*
		 * TLS Extensions - required by modern servers.
		 */
		ByteArrayOutputStream extensions = new ByteArrayOutputStream();

		// SNI (Server Name Indication) extension - type 0x0000
		// Required by most modern servers for virtual hosting
		if (hostname != null && hostname.length() > 0) {
			byte[] hostnameBytes = hostname.getBytes("ASCII");
			int sniDataLen = hostnameBytes.length + 5; // 2 (list len) + 1 (type) + 2 (name len) + hostname
			extensions.write(0x00); // extension type high byte
			extensions.write(0x00); // extension type low byte (SNI = 0)
			enc16be(sniDataLen, extensions);
			enc16be(hostnameBytes.length + 3, extensions); // server name list length
			extensions.write(0x00); // name type: host_name (0)
			enc16be(hostnameBytes.length, extensions);
			extensions.write(hostnameBytes);
		}

		// supported_versions extension - type 0x002b (43)
		// Required for TLS 1.3 negotiation
		extensions.write(0x00); // extension type high byte
		extensions.write(0x2b); // extension type low byte (supported_versions = 43)
		// For TLS 1.3: list all versions we want to try
		// For older versions: just list that version
		if (version >= 0x0304) {
			// TLS 1.3 - list TLS 1.3, 1.2, 1.1, 1.0
			extensions.write(0x00); // extension length high byte
			extensions.write(0x09); // extension length low byte (1 + 4*2 = 9)
			extensions.write(0x08); // versions length (4 versions * 2 bytes)
			extensions.write(0x03); extensions.write(0x04); // TLS 1.3
			extensions.write(0x03); extensions.write(0x03); // TLS 1.2
			extensions.write(0x03); extensions.write(0x02); // TLS 1.1
			extensions.write(0x03); extensions.write(0x01); // TLS 1.0
		} else {
			// Older version - just list requested version
			extensions.write(0x00); // extension length high byte
			extensions.write(0x03); // extension length low byte
			extensions.write(0x02); // versions length
			extensions.write(version >>> 8);
			extensions.write(version);
		}

		// signature_algorithms extension - type 0x000d (13)
		// Required by many servers, especially for TLS 1.2+
		extensions.write(0x00); // extension type high byte
		extensions.write(0x0d); // extension type low byte (signature_algorithms = 13)
		extensions.write(0x00); // extension length high byte
		extensions.write(0x14); // extension length low byte (20 bytes)
		extensions.write(0x00); // algorithms length high byte
		extensions.write(0x12); // algorithms length low byte (18 bytes = 9 algorithms)
		// RSA-PSS algorithms (TLS 1.3)
		extensions.write(0x08); extensions.write(0x04); // rsa_pss_rsae_sha256
		extensions.write(0x08); extensions.write(0x05); // rsa_pss_rsae_sha384
		extensions.write(0x08); extensions.write(0x06); // rsa_pss_rsae_sha512
		// ECDSA algorithms
		extensions.write(0x04); extensions.write(0x03); // ecdsa_secp256r1_sha256
		extensions.write(0x05); extensions.write(0x03); // ecdsa_secp384r1_sha384
		extensions.write(0x06); extensions.write(0x03); // ecdsa_secp521r1_sha512
		// RSA PKCS#1 algorithms (legacy)
		extensions.write(0x04); extensions.write(0x01); // rsa_pkcs1_sha256
		extensions.write(0x05); extensions.write(0x01); // rsa_pkcs1_sha384
		extensions.write(0x06); extensions.write(0x01); // rsa_pkcs1_sha512

		// supported_groups extension - type 0x000a (10)
		// Required for key exchange, especially ECDHE
		extensions.write(0x00); // extension type high byte
		extensions.write(0x0a); // extension type low byte (supported_groups = 10)
		extensions.write(0x00); // extension length high byte
		extensions.write(0x08); // extension length low byte
		extensions.write(0x00); // groups length high byte
		extensions.write(0x06); // groups length low byte (3 groups * 2 bytes)
		extensions.write(0x00); extensions.write(0x17); // secp256r1
		extensions.write(0x00); extensions.write(0x18); // secp384r1
		extensions.write(0x00); extensions.write(0x19); // secp521r1

		// key_share extension - type 0x0033 (51)
		// Required for TLS 1.3: provide ephemeral ECDH key share
		if (version >= 0x0304) {
			try {
				java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
				kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
				java.security.KeyPair kp = kpg.generateKeyPair();
				java.security.interfaces.ECPublicKey ecPub = (java.security.interfaces.ECPublicKey) kp.getPublic();
				// Encode as uncompressed point: 04 || x || y (65 bytes for secp256r1)
				byte[] x = ecPub.getW().getAffineX().toByteArray();
				byte[] y = ecPub.getW().getAffineY().toByteArray();
				byte[] point = new byte[65];
				point[0] = 0x04;
				// Copy x (right-aligned, 32 bytes)
				int xOff = x.length > 32 ? x.length - 32 : 0;
				int xLen = Math.min(x.length, 32);
				System.arraycopy(x, xOff, point, 1 + (32 - xLen), xLen);
				// Copy y (right-aligned, 32 bytes)
				int yOff = y.length > 32 ? y.length - 32 : 0;
				int yLen = Math.min(y.length, 32);
				System.arraycopy(y, yOff, point, 33 + (32 - yLen), yLen);

				// key_share extension structure:
				// 2 bytes: client_shares length
				// 2 bytes: named group (0x0017 = secp256r1)
				// 2 bytes: key_exchange length (65)
				// 65 bytes: key_exchange data
				int keyShareDataLen = 2 + 2 + 2 + point.length; // 71
				extensions.write(0x00); // extension type high byte
				extensions.write(0x33); // extension type low byte (key_share = 51)
				enc16be(keyShareDataLen, extensions); // extension data length
				enc16be(2 + 2 + point.length, extensions); // client_shares length (69)
				extensions.write(0x00); extensions.write(0x17); // named group: secp256r1
				enc16be(point.length, extensions); // key_exchange length
				extensions.write(point);
			} catch (Exception e) {
				logger.warn("Failed to generate key_share for TLS 1.3", e);
			}
		}

		// ec_point_formats extension - type 0x000b (11)
		extensions.write(0x00); // extension type high byte
		extensions.write(0x0b); // extension type low byte (ec_point_formats = 11)
		extensions.write(0x00); // extension length high byte
		extensions.write(0x02); // extension length low byte
		extensions.write(0x01); // formats length
		extensions.write(0x00); // uncompressed

		// Write extensions to main buffer
		byte[] extBytes = extensions.toByteArray();
		enc16be(extBytes.length, b);
		b.write(extBytes);

		/*
		 * We now get the message as a blob. The message length
		 * must be adjusted in the header.
		 */
		byte[] msg = b.toByteArray();
		enc24be(msg.length - 4, msg, 1);
		return msg;
	}
	
	/**
	 * Convert a strength constant to a human-readable description.
	 * @param strength one of UNASSIGNED, CLEAR, WEAK, MEDIUM, or STRONG
	 * @return descriptive string (e.g., "strong encryption (96-bit or more)")
	 */
	static final String strengthString(int strength)
	{
		switch (strength) {
		case UNASSIGNED: return "unassigned evaluation";
		case CLEAR:  return "no encryption";
		case WEAK:   return "weak encryption (40-bit)";
		case MEDIUM: return "medium encryption (56-bit)";
		case STRONG: return "strong encryption (96-bit or more)";
		default:
			throw new Error("Unknown strength evalution: " + strength);
		}
	}


	
	/**
	 * Look up the name of a cipher suite by its numeric ID, using the given naming convention.
	 * @param suite cipher suite ID
	 * @param cipher_name_convention naming convention (IANA, OpenSSL, etc.)
	 * @return cipher suite name, or "TLS_UNIDENTIFIED(0xXXXX)" if not found
	 */
	static final String cipherSuiteString(int suite, ISession.CIPHER_NAME_CONVENTION cipher_name_convention)
	{
		ensureCipherMapInitialized();
		CipherSuite cs = CIPHER_SUITES.get(suite);
		String ciphername = String.format("TLS_UNIDENTIFIED(0x%04X)", suite);
		
		//Need to map Enum name to String name of the cipher suite since that's way it's stored in JSON.
		if( cs != null ) {
			ciphername = (String)cs.names.get(cipher_name_convention.toString());
		}
		return ciphername;
	}

	/**
	 * Look up the name of an SSLv2 cipher suite by its numeric ID, using the given naming convention.
	 * @param suite SSLv2 cipher suite ID (3-byte encoding)
	 * @param cipher_name_convention naming convention (IANA, OpenSSL, etc.)
	 * @return cipher suite name, or "TLS_UNIDENTIFIED(0xXX,XX,XX)" if not found
	 */
	static final String cipherSuiteStringV2(int suite, ISession.CIPHER_NAME_CONVENTION cipher_name_convention)
	{
		CipherSuite cs = CIPHER_SUITES.get(suite);
		String ciphername = String.format("TLS_UNIDENTIFIED(0x%02X,%02X,%02X)",
				suite >> 16, (suite >> 8) & 0xFF, suite & 0XFF);
		
		//Need to map Enum name to String name of the cipher suite since that's way it's stored in JSON.
		if (cs != null) {
			ciphername = (String)cs.names.get(cipher_name_convention.toString());
		}
		return ciphername; 
	}

	//todo need to fix this asap
	private static final void makeCS(int suite, Map names, int strength)
	{
		CipherSuite cs = new CipherSuite();
		cs.suite = suite;
		cs.names = names;
//		cs.isCBC = isCBC;
		cs.strength = strength;
		CIPHER_SUITES.put(suite, cs);
	}
	
}


