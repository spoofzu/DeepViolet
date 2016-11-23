package com.mps.deepviolet.api;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.mps.deepviolet.util.LogUtils;

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
 * {@code IDSession session = DVFactory.initializeSession(url);
 * IDVEng eng = DVFactory.getIDVEng(session);
 * IDVCipherSuite[] ciphers = eng.getHostCipherSuites();
 * ...iterate over the ciphers, do cool stuff, makes your own custom reports or UI...}
 * </pre>
 * 
 * <pre>
 * {@code com.mps.deepviolet.api.samples}
 * </pre>
 * 
 * @author Milton Smith
 *
 */
public class DVFactory {

	// Initialize logging before we do anything
	static {
		LogUtils.logInit();
	}

	private DVFactory() {
	}

	/**
	 * Initialize a session. Required for obtaining an instance of IDVOnEng.
	 * 
	 * @param url
	 *            URL of the host to perform SSL/TLS scan
	 * @return Initialized session instance for this host.
	 * @throws DVException
	 *             Thrown on problems initializing host.
	 */
	public static final synchronized IDVSession initializeSession(URL url) throws DVException {
		ArrayList<IDVHost> list = new ArrayList<IDVHost>();
		MutableDVSession session = null;

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = null;

		try {
			socket = (SSLSocket) factory.createSocket(url.getHost(), url.getDefaultPort());

			// Add interfaces
			InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
			for (InetAddress address : addresses) {
				String host = address.getHostName();
				String ip = address.getHostAddress();
				String canonical = address.getCanonicalHostName();
				ImmutableDVHost dvhost = new ImmutableDVHost(host, ip, canonical, url);
				list.add(dvhost);
			}

			// TODO: Fix types, e.g. int for size of receive buffer
			String soKeepalive = Boolean.toString(socket.getKeepAlive());
			String soRcvbuf = Integer.toString(socket.getReceiveBufferSize());
			String soLinger = Integer.toString(socket.getSoLinger());
			String soTimeout = Integer.toString(socket.getSoTimeout());
			String trafficClass = Integer.toString(socket.getTrafficClass());
			String clientAuthReq = Boolean.toString(socket.getNeedClientAuth());
			String clientAuthWant = Boolean.toString(socket.getWantClientAuth());
			String tcpNodelay = Boolean.toString(socket.getTcpNoDelay());
			String soReuseaddr = Boolean.toString(socket.getReuseAddress());
			String soSendbuff = Integer.toString(socket.getSendBufferSize());
			// TODO OOBINLINE causes socket to error, leave for now
			// String oobinline = Boolean.toString(socket.getOOBInline());

			// Grab enabled protocols as reported by socket
			String enabledProtocols = String.join(",", socket.getEnabledProtocols());

			session = new MutableDVSession(url, (IDVHost[]) list.toArray(new ImmutableDVHost[0]));
			session.setProperty("SO_KEEPALIVE", soKeepalive);
			session.setProperty("SO_RCVBUF", soRcvbuf);
			session.setProperty("SO_LINGER", soLinger);
			session.setProperty("SO_TIMEOUT", soTimeout);
			session.setProperty("SO_REUSEADDR", soReuseaddr);
			session.setProperty("SO_SENDBUFF", soSendbuff);
			session.setProperty("CLIENT_AUTH_REQ", clientAuthReq);
			session.setProperty("CLIENT_AUTH_WANT", clientAuthWant);
			session.setProperty("TRAFFIC_CLASS", trafficClass);
			session.setProperty("TCP_NODELAY", tcpNodelay);
			session.setProperty("ENABLED_PROTOCOLS", enabledProtocols);
		} catch (Exception e) {
			throw new DVException(e);
		} finally {
			if (socket != null) {
				try {
					socket.close();
				} catch (IOException ignored) {
				}
			}
		}
		return session;
	}

//	/**
//	 * Retrieve an instance of IDVOffEng. Provided since there are some offline
//	 * functions that don't require an initialized host. For example, reading
//	 * PEM encoded X.509 certificates.
//	 * 
//	 * @return Engine instance for offline functions
//	 */
//	public static final synchronized getDVOffEng() {
//		URL localhost = null;
//		try {
//			localhost = new URL("https://localhost/");
//		} catch (MalformedURLException e) {
//			e.printStackTrace();
//		}
//		return new DVEng(new MutableDVSession(localhost, new IDVHost[0]));
//	}

	/**
	 * Retrieve an instance of IDVOnEng. Use this method for online functions
	 * against an initialize host.
	 * 
	 * @param session
	 *            Initialized session from previous call to initializeSession(URL)
	 * @return Engine instance for offline functions
	 * @see #initializeSession(URL)
	 */
	public static final synchronized IDVEng getDVEng(IDVSession session) {
		return new DVEng(session);
	}
}
