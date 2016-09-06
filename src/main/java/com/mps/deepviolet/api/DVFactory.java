package com.mps.deepviolet.api;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;
import ch.qos.logback.core.joran.spi.JoranException;

import com.mps.deepviolet.util.FileUtils;

/**
 * Initial entry point for all DeepViolet API work.
 * <p>
 * The DeepViolet API is divided across two
 * main functions, online and offline reporting.  Online reports like
 * SSL/TLS DAST scans require an online host.  However, other features may
 * be used offline like processing and printing PEM encoded X.509 certificates.
 * To get an idea for how to use DeepViolet API take a look at the following
 * examples.
 * <pre>
 * {@code IDSession session = DVFactory.initializeSession(url);
 * IDVOnEng eng = DVFactory.getIDVOnEng(session);
 * IDVCipherSuite[] ciphers = eng.getHostCipherSuites();
 * ...iterate over the ciphers, do cool stuff, makes your own custom reports or UI...}
 * </pre>
 * If you only want to print the cipher suites you can do something like
 * this.
 * <pre>
 * {@code StringBuffer con = new StringBuffer(2500);
 * IDSession session = DVFactory.initializeSession(url);
 * IDVOnEng eng = DVFactory.getIDVOnEng(session);
 * IDVOnPrint p = getDVOnPrint(con);
 * p.printSupportedCipherSuites();
 * ...prints some raw text to the console buffer and active logger...}
 * </pre>
 * Also have a look at the code in the samples package for ideas where to begin,
 * <pre>
 * {@code com.mps.deepviolet.api.samples}
 * </pre>
 * 
 * @author Milton Smith
 *
 */
public class DVFactory {
	
	private DVFactory() {}

	/**
	 * Initialize a session.  Required for obtaining an instance of IDVOnEng.
	 * @param url URL of the host to perform SSL/TLS scan
	 * @return Intialized session instance for this host.
	 * @throws DVException Thrown on problems initializing host. 
	 */
	public static final synchronized IDVSession initializeSession(URL url) throws DVException {
		
		
		ArrayList<IDVHost> list = new ArrayList<IDVHost>();
        MutableDVSession session = null;
		
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = null;
      
		try {
			
			socket = (SSLSocket)factory.createSocket(url.getHost(), url.getDefaultPort());
	        
	        // Add interfaces
			InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
		    for (InetAddress address : addresses ) {
		    	String host = address.getHostName();
		        String ip = address.getHostAddress();
		        String cannonical = address.getCanonicalHostName();
		        ImmutableDVHost dvhost = new ImmutableDVHost(host, ip, cannonical, url);
		        list.add( dvhost );
	        }
		
			String so_keepalive = Boolean.toString( socket.getKeepAlive() );
	        String so_rcvbuf = Integer.toString( socket.getReceiveBufferSize() );
	        String so_linger = Integer.toString( socket.getSoLinger() );
	        String so_timeout = Integer.toString( socket.getSoTimeout() );
	        String traffic_class = Integer.toString( socket.getTrafficClass() );
	        String client_auth_req = Boolean.toString( socket.getNeedClientAuth() );
	        String client_auth_want = Boolean.toString( socket.getWantClientAuth() );
	        String tcp_nodelay = Boolean.toString( socket.getTcpNoDelay() );
		    String soreuseaddr = Boolean.toString(socket.getReuseAddress());
		    String sosendbuff = Integer.toString( socket.getSendBufferSize() );
		    //TODO OOBINLINE causes socket to error, leave for now
	        //String oobinline = Boolean.toString(socket.getOOBInline());
		    
		    // Grab enabled protocols as reported by socket
	        String[] eprotos = socket.getEnabledProtocols();
	        StringBuffer buff = new StringBuffer();
	        for( String p : eprotos ) {
	        	if( buff.length() > 0 ) {
	        		buff.append(',');
	        	}
	        	buff.append(p);
	        }
	        String enabled_protocols = buff.toString();
		    
		    session = new MutableDVSession(url, (IDVHost[])list.toArray(new ImmutableDVHost[0]));
		    session.setProperty("SO_KEEPALIVE",so_keepalive);
		    session.setProperty("SO_RCVBUF",so_rcvbuf);
		    session.setProperty("SO_LINGER",so_linger);
		    session.setProperty("SO_TIMEOUT",so_timeout);
		    session.setProperty("SO_REUSEADDR",soreuseaddr);
		    session.setProperty("SO_SENDBUFF",sosendbuff);
		    session.setProperty("CLIENT_AUTH_REQ",client_auth_req);
		    session.setProperty("CLIENT_AUTH_WANT",client_auth_want);
		    session.setProperty("TRAFFIC_CLASS",traffic_class);
		    session.setProperty("TCP_NODELAY",tcp_nodelay);
		    session.setProperty("ENABLED_PROTOCOLS",enabled_protocols);

		} catch ( Exception e ) {
		
			DVException e1 = new DVException(e);
			throw e1;
			
		} finally {
			
			if( socket !=null) {
				try {
					socket.close();
				} catch (IOException e) {}
			}
		
		}
		
		return session;
		
	}

	/**
	 * Retrieve an instance of IDVOffEng.  Provided since there are 
	 * some offline functions that don't require an initialized host.
	 * For example, reading PEM encoded X.509 certificates.
	 * @return Engine instance for offline functions
	 */
	public static final synchronized IDVOffEng getDVOffEng() {
		
		URL localhost =null;
		try {
			localhost = new URL("https://localhost/");
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		
		return new DVEng(new  MutableDVSession(localhost, new IDVHost[0]) );
		
	}
	
	/**
	 * Retrieve an instance of IDVOnEng.  Use this method for online
	 * functions against an intialized host.  
	 * @param session Inialized session from previous call to initializeSession(URL)
	 * @return Engine instance for offline functions
	 * @see #initializeSession(URL)
	 */
	public static final synchronized IDVOnEng getDVEng( IDVSession session ) {
		
		return new DVEng( session );
		
	}
	
}
