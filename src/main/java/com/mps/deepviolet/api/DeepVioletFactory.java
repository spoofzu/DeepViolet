package com.mps.deepviolet.api;

import java.io.InputStream;
import java.net.URL;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;
import com.mps.deepviolet.api.ai.AiAnalysisService;
import com.mps.deepviolet.api.ai.IAiAnalysisService;
import com.mps.deepviolet.api.tls.ClientHelloConfig;
import com.mps.deepviolet.api.tls.TlsMetadata;
import com.mps.deepviolet.api.tls.TlsSocket;
/**
 * Initial entry point for all DeepViolet API work.
 * <p>
 * The DeepViolet API is divided across two main functions, online and offline
 * reporting. Online reports like SSL/TLS DAST scans require an online host.
 * However, other features may be used offline like processing and printing PEM
 * encoded X.509 certificates. To get an idea for how to use DeepViolet API take
 * a look at the following examples.
 * 
 * <pre>
 * {@code IDSession session = DeepVioletFactory.initializeSession(url);
 * IEngine eng = DeepVioletFactory.getIDVEng(session);
 * ICipherSuite[] ciphers = eng.getHostCipherSuites();
 * ...iterate over the ciphers, do cool stuff, makes your own custom reports or UI...}
 * </pre>
 * 
 * <pre>
 * {@code com.mps.deepviolet.samples}
 * </pre>
 * 
 * @author Milton Smith
 */
public class DeepVioletFactory {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.DeepVioletFactory");

	private DeepVioletFactory() {
	}

	/**
	 * Initialize a session. Required for obtaining an instance of IEngine.
	 * 
	 * @param url
	 *            URL of the host to perform SSL/TLS scan
	 * @return Initialized session instance for this host.
	 * @throws DeepVioletException
	 *             Thrown on problems initializing host.
	 */
	public static final ISession initializeSession(URL url) throws DeepVioletException {
		ArrayList<IHost> list = new ArrayList<IHost>();

		try {
			int sslPort = url.getDefaultPort();
			if (url.getPort() > 0) {
				sslPort = url.getPort();
			}

			// Step 1: Raw TLS socket — primary metadata source
			// No JSSE, no trust enforcement. Works with any server (good or bad certs).
			TlsMetadata tlsMeta = TlsSocket.connect(url.getHost(), sslPort,
					ClientHelloConfig.defaultConfig());

			if (tlsMeta == null || !tlsMeta.isConnectionSucceeded()) {
				String reason = tlsMeta != null ? tlsMeta.getFailureReason() : "connection failed";
				throw new DeepVioletException("Failed to connect to " + url.getHost() + ":" + sslPort
						+ " — " + reason);
			}

			// Extract negotiated protocol and cipher (map hex to IANA name)
			String protocol = tlsMeta.getVersionString();
			String cipher = CipherSuiteUtil.cipherSuiteString(
					tlsMeta.getCipherSuite(), ISession.CIPHER_NAME_CONVENTION.IANA);

			// SCTs from all sources
			List<byte[]> scts = tlsMeta.getAllSCTs();

			// OCSP stapled response
			byte[] stapledOcspResponse = tlsMeta.getStapledOcspResponse();

			// Step 2: DNS resolution
			InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
			for (InetAddress address : addresses) {
				String host = address.getHostName();
				String ip = address.getHostAddress();
				String canonical = address.getCanonicalHostName();
				ImmutableHost dvhost = new ImmutableHost(host, ip, canonical, url);
				list.add(dvhost);
			}

			// Step 3: Assemble session
			MutableSession session = new MutableSession(url,
					(IHost[]) list.toArray(new ImmutableHost[0]));

			// TCP socket defaults (raw socket — SSL-specific properties not applicable)
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.SO_KEEPALIVE, "false");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.SO_RCVBUF, "65536");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.SO_LINGER, "-1");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.SO_TIMEOUT, "10000");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.SO_REUSEADDR, "false");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.SO_SENDBUFF, "65536");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.CLIENT_AUTH_REQ, "false");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.CLIENT_AUTH_WANT, "false");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.TRAFFIC_CLASS, "0");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.TCP_NODELAY, "false");
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.ENABLED_PROTOCOLS, protocol);

			// Negotiated protocol and cipher from raw TLS socket
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_PROTOCOL, protocol);
			session.setSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_CIPHER_SUITE, cipher);

			// SCTs and OCSP
			session.setSCTs(scts);
			if (stapledOcspResponse != null) {
				session.setStapledOcspResponse(stapledOcspResponse);
			}

			return session;

		} catch (DeepVioletException e) {
			throw e;
		} catch (Exception e) {
			throw new DeepVioletException(e);
		}
	}

	/**
	 * Retrieve an instance of IEngine. Use this method for online functions
	 * against an initialize host.  Calls {@link #getEngine(ISession, CIPHER_NAME_CONVENTION)} and
	 * passes CIPHER_NAME_CONVENTION.IANA.
	 *
	 * @param session
	 *            Initialized session from previous call to initializeSession(URL)
	 * @return Engine instance for offline functions
	 * @throws DeepVioletException
	 *           Thrown on problems initializing host.
	 * @see #initializeSession(URL)
	 */
	public static final IEngine getEngine(ISession session) throws DeepVioletException {
		return new DeepVioletEngine(session, ISession.CIPHER_NAME_CONVENTION.IANA);
	}
	
	/**
	 * Retrieve an instance of IEngine. Use this method for online functions
	 * against an initialize host.
	 *
	 * @param session
	 *            Initialized session from previous call to initializeSession(URL)
	 *  @param cipher_name_convention Cipher suite name convention.
	 * @return Engine instance for offline functions
	 * @throws DeepVioletException
	 *           Thrown on problems initializing host.
	 * @see #initializeSession(URL)
	 */
	public static final IEngine getEngine(ISession session, ISession.CIPHER_NAME_CONVENTION cipher_name_convention ) throws DeepVioletException {
		return new DeepVioletEngine(session, cipher_name_convention);
	}
	
	/**
	 * Retrieve an instance of IEngine. Use this method to post regular status to your BackgroundTask.
	 * 
	 * @param session
	 *            Initialized session from previous call to initializeSession(URL)
	 * @param cipher_name_convention Cipher suite name convention.
	 * @param dvtask BackgroundTask to update with user displayable status information.
	 * @return Engine instance for offline functions
	 * @throws DeepVioletException
	 *           Thrown on problems initializing host.
	 * @see #initializeSession(URL)
	 */
	public static final IEngine getEngine(ISession session, ISession.CIPHER_NAME_CONVENTION cipher_name_convention, BackgroundTask dvtask ) throws DeepVioletException {
		return new DeepVioletEngine(session, cipher_name_convention, dvtask);
	}

	/**
	 * Retrieve an instance of IEngine with protocol version filtering.
	 *
	 * @param session Initialized session from previous call to initializeSession(URL)
	 * @param cipher_name_convention Cipher suite name convention.
	 * @param dvtask BackgroundTask to update with user displayable status information.
	 * @param enabledProtocols Set of protocol version codes to probe (e.g. 0x0303 for TLS 1.2), or null for all.
	 * @return Engine instance for offline functions
	 * @throws DeepVioletException Thrown on problems initializing host.
	 * @see #initializeSession(URL)
	 */
	public static final IEngine getEngine(ISession session, ISession.CIPHER_NAME_CONVENTION cipher_name_convention, BackgroundTask dvtask, java.util.Set<Integer> enabledProtocols ) throws DeepVioletException {
		return new DeepVioletEngine(session, cipher_name_convention, dvtask, enabledProtocols);
	}

	/**
	 * Load a custom cipher map from a stream, fully replacing the built-in map.
	 * The stream must contain valid cipher map YAML with a {@code cipher_suites} key.
	 *
	 * @param is InputStream containing cipher map YAML
	 * @throws DeepVioletException Thrown on problems loading the cipher map
	 */
	public static synchronized void loadCipherMap(InputStream is) throws DeepVioletException {
		try {
			CipherSuiteUtil.loadCipherMapFromStream(is);
		} catch (Exception e) {
			throw new DeepVioletException("Failed to load cipher map: " + e.getMessage(), e);
		}
	}

	/**
	 * Get the AI analysis service instance.
	 *
	 * @return IAiAnalysisService for direct AI interactions
	 */
	public static IAiAnalysisService getAiService() {
		return new AiAnalysisService();
	}

	/**
	 * Reset the cipher map to the built-in default.
	 * The next operation that needs the cipher map will re-initialize from the classpath resource.
	 *
	 * @throws DeepVioletException Thrown on problems resetting the cipher map
	 */
	public static synchronized void resetCipherMap() throws DeepVioletException {
		try {
			CipherSuiteUtil.resetCipherMap();
		} catch (Exception e) {
			throw new DeepVioletException("Failed to reset cipher map: " + e.getMessage(), e);
		}
	}
}
