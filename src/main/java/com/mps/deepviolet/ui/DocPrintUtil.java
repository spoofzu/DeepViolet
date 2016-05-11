package com.mps.deepviolet.ui;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyledDocument;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.suite.CipherSuiteUtil;
import com.mps.deepviolet.suite.Protocol;
import com.mps.deepviolet.suite.ServerMetadata;

/**
 * Report utility that controls how each report section is printed.
 * @author Milton Smith
 */
public class DocPrintUtil {

	private static final String VERSION = "V1.2.000";
	
	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.ui.DocPrintUtil");
	
	private static final String EOL = System.getProperty("line.separator");
	
	/**
	 * Print start of scan report.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printReportHeader( StringBuffer con, URL url ) {
		
		Date d = new Date();
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"***********************************************************************");
		DocPrintUtil.println(con,"*  NOTICE: THIS SOFTWARE IS PROVIDED FOR RESEARCH PURPOSES AND NOT    *");
		DocPrintUtil.println(con,"*          RECOMMENDED FOR USE ON PRODUCTION SYSTEMS.  SEE PROJECT    *");
		DocPrintUtil.println(con,"*          INFORMATION ON GITHUB FOR FURTHER DETAILS,                 *");
		DocPrintUtil.println(con,"*          https://github.com/spoofzu/DeepViolet                      *");
		DocPrintUtil.println(con,"***********************************************************************");
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Report run information]");
		DocPrintUtil.println(con,"DeepViolet "+VERSION);
		DocPrintUtil.println(con,"Report generated on "+d.toString());
		if( url != null ) {
			DocPrintUtil.println(con,"Target url "+url.toString());	
		}
		//TODO: PRINT THE LOGBACK FILE LOCATION, LOCATION OF CACERTS, AND VERSION OF JAVA
		
	}
	
	/**
	 * Print a list of HTTPS response heads for the given URL
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printHostHttpResponseHeaders( StringBuffer con, URL url ) {
		
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[HTTP(S) response headers]");
		
		try {
			
			Map<String, List<String>> headers = CipherSuiteUtil.getHttpResponseHeaders(url);
			
			for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
				
				String key = (String)entry.getKey();
				
				List<String> vlist = entry.getValue();
				
				for ( String value: vlist ) {
					
					key = (key == null ) ? "<null>" : key;
					key = (key.length() > 5000) ? key.substring(0,5000)+"[truncated by DeepViolet sz="+key.length()+"]" : key;
	
					value = (value == null ) ? "<null>" : value;
					value = (value.length() > 5000) ? value.substring(0,5000)+"[truncated by DeepViolet sz="+key.length()+"]" : value;	
					
			      	DocPrintUtil.println(con, key+" : "+value );
					
				}
				
			}
        	
		} catch (SSLHandshakeException e ) {
			
			if( e.getMessage().indexOf("PKIX") > 0 ) {
				DocPrintUtil.println(con,"Certificate chain failed validation." );
				DocPrintUtil.println(con,"");
				logger.error("Certificate chain failed validation. err="+e.getMessage(),e );
			}else{
				DocPrintUtil.println(con,"SSLHandshakeException. err="+e.getMessage() );
				DocPrintUtil.println(con,"");
				logger.error("SSLHandshakeException. err="+e.getMessage(),e );
			}
        	
		} catch (Exception e) {
		
        	DocPrintUtil.println(con,"Error printing HTTP headers. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
        	logger.error("Error printing HTTP headers. err="+e.getMessage(),e);
		
		}
		
		
	}
	
	/**
	 * Print various information about host system under assessment.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printHostInformation(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Host information]");

        try {
        	InetAddress[] addresses = InetAddress.getAllByName(url.getHost());

	        for (InetAddress address : addresses ) {
	        	
	            try { 
	            	StringBuffer buff = new StringBuffer();
	            	buff.append( "host="+address.getHostName()+" ["+address.getHostAddress()+"], ");
	            	buff.append("canonical="+address.getCanonicalHostName());
	            	DocPrintUtil.println(con, buff.toString());
		        } catch( Exception e ){
		        	DocPrintUtil.println(con,"skipping host, err="+e.getMessage());
		        	DocPrintUtil.println(con, "" );
		        	logger.warn("Skipping host. err="+e.getMessage(),e);
		        }     
	       
	        }
	        
		} catch (UnknownHostException e) {
        	DocPrintUtil.println(con,"Can't fetch host. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
        	logger.error("Can't fetch host. err="+e.getMessage(),e);
		}
	
	}
	
	public static final void printServerAnalysis(StringBuffer con, URL url) {
		
		//DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Server analysis]");
		DocPrintUtil.println(con,"DISABLED, Uncomment code and recompile to experiment.");

        try {
        	
        	ServerMetadata m = CipherSuiteUtil.getServerMetadataInstance(url);
        
        	//TODO: Displays scalar properties but skips any vector quantities (but no vector quantities for now)
			for (String key : m.getKeys("analysis")) {
				
				if( m.isScalarType("analysis", key) )
					DocPrintUtil.println(con, key+"="+m.getScalarValue("analysis",key));

			}
	        
		} catch (Exception e) {
        	DocPrintUtil.println(con,"Can't perform server analysis. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
        	logger.error("Can't perform server analysis. err="+e.getMessage(),e);
		}
	
	}
	
//	/**
//	 * Print section for the supported ciphersuites.
//	 * @param con StringBuffer for the output report.
//	 * @param url Target URL of assessment.
//	 */
//	public static final void printSupportedCipherSuites(StringBuffer con, URL url) {
//		
//		DocPrintUtil.println(con,"");
//		DocPrintUtil.println(con,"[Host supported server cipher suites]");
//		
//		
//		try {
//		
//			String[] server_ciphers = CipherSuiteUtil.getServerSupportedCiphersuites(url);
//				
//				Protocol[] protocols = CipherSuiteUtil.getClientSupportedProtocols();
//				
//				for ( Protocol protocol : protocols ) {
//					
//					String p = protocol.getName();
//					
//					DocPrintUtil.println(con,p);
//					
//				    for ( String cipher : server_ciphers ) {
//				    	
//				    	if ( protocol.hasCipher(cipher) ) {
//				    		
//				    		String strength = CipherSuiteUtil.getStrength(cipher);
//				    		
//							DocPrintUtil.print(con,"  - (SUPPORTED) ");
//							DocPrintUtil.print(con,cipher);
//							DocPrintUtil.print(con," (STRENGTH=");
//							DocPrintUtil.print(con,strength);
//							DocPrintUtil.println(con," )");
//		
//				    	}
//				    	
//				    }
//				   		
//				}
//		
//		} catch (Exception e) {
//        	DocPrintUtil.println(con,"Problem processing server ciphers. err="+e.getMessage() );
//        	logger.error("Problem processing server ciphers. err="+e.getMessage(),e);
//		}
//
//			
//	}
	
	/**
	 * Print section for the supported ciphersuites.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printSupportedCipherSuites(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Host supported server cipher suites]");
		
		
		try {
		
			Map<String,List<String>> all_ciphers = new HashMap<String, List<String>>();
			ServerMetadata m = CipherSuiteUtil.getServerMetadataInstance( url );
			if( m == null ) {
				logger.error("No server metadata returned.");
				return;
			}
			if( m.containsKey("getServerMetadataInstance","SSLv2") ) all_ciphers.put("SSLv2",m.getVectorValue("getServerMetadataInstance","SSLv2"));
			if( m.containsKey("getServerMetadataInstance","SSLv3") ) all_ciphers.put("SSLv3",m.getVectorValue("getServerMetadataInstance","SSLv3"));
			if( m.containsKey("getServerMetadataInstance","TLSv1.0") ) all_ciphers.put("TLSv1.0",m.getVectorValue("getServerMetadataInstance","TLSv1.0"));
			if( m.containsKey("getServerMetadataInstance","TLSv1.1") ) all_ciphers.put("TLSv1.1",m.getVectorValue("getServerMetadataInstance","TLSv1.1"));
			if( m.containsKey("getServerMetadataInstance","TLSv1.2") ) all_ciphers.put("TLSv1.2",m.getVectorValue("getServerMetadataInstance","TLSv1.2"));
			
				Set<String> all_cipher_keys = all_ciphers.keySet();
			
				for( String tls_version :  all_cipher_keys  ) {
					
					List<String> ciphers = all_ciphers.get( tls_version );
					
					DocPrintUtil.println (con, tls_version);
					
						Iterator<String> i = ciphers.iterator();
						
						while (i.hasNext() ) {
							
							String cipher = i.next();
							
							String ciphernameonly = cipher;
							
							int idx = cipher.indexOf("(0x", 0);
							
							if( idx != -1 )
								ciphernameonly = cipher.substring(0,idx);
									
							String strength = "UNKNOWN";
							
							if( ciphernameonly.length() > 0 ) {
								
								strength = CipherSuiteUtil.getStrength(ciphernameonly);
							
								if( cipher.startsWith(CipherSuiteUtil.NO_CIPHERS)) 
									strength = "";
							}	
								
							DocPrintUtil.println (con, " - "+cipher+" ("+strength+")");
							
						}
					
					
				}
				
		
		} catch (Exception e) {
        	DocPrintUtil.println(con,"Problem processing server ciphers. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
        	logger.error("Problem processing server ciphers. err="+e.getMessage(),e);
		}

			
	}
	
	/**
	 * Print section for the connection characteristics.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printConnectionCharacteristics(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con, "" );
		DocPrintUtil.println(con, "[Connection characteristics]" );
		
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket;
		try {
			socket = (SSLSocket)factory.createSocket(url.getHost(), url.getDefaultPort());
			
			DocPrintUtil.println(con, "SO_KEEPALIVE="+socket.getKeepAlive() );
			DocPrintUtil.println(con, "SO_RECBUF="+socket.getReceiveBufferSize() );
			DocPrintUtil.println(con, "SO_LINGER="+socket.getSoLinger() );
			DocPrintUtil.println(con, "SO_TIMEOUT="+socket.getSoTimeout() );
			DocPrintUtil.println(con, "Traffic Class="+socket.getTrafficClass() );
			DocPrintUtil.println(con, "Client Auth Required="+socket.getNeedClientAuth());
			DocPrintUtil.println(con, "SO_REUSEADDR="+socket.getReuseAddress() );
			DocPrintUtil.println(con, "TCP_NODELAY="+socket.getTcpNoDelay() );
	        
	        socket.close();
			
		} catch (UnknownHostException e) {
        	DocPrintUtil.println(con,"Problem getting connection information. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
			logger.error( "Problem getting connection information. err="+e.getMessage(), e);
		} catch (IOException e) {
			DocPrintUtil.println(con,"I\\O problem reading socket. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
			logger.error( "I\\O problem reading socket. err="+e.getMessage(), e);
		}  		
	}
	
	public static final void printServerCertificate(StringBuffer con, String file ) {
		
		  try {
			  File f = new File(file);
		      FileInputStream fis = new FileInputStream(f);
		      
		      CertificateFactory cf = CertificateFactory.getInstance("X.509");
		      Collection c = cf.generateCertificates(fis);
		      Iterator i = c.iterator();
		      while (i.hasNext()) {
		    	  X509Certificate cert = (X509Certificate)i.next();
				 printTrustState( con, cert );
		    	 printX509Certificate( con, cert );
		      }
		  } catch( FileNotFoundException e ) {
				DocPrintUtil.println(con,"Read certificate failed. reason=file not found.  file="+file );
				DocPrintUtil.println(con,"");
		  } catch( CertificateException e ) {
				DocPrintUtil.println(con,"Read certificate failed.  reason="+e.getMessage()+" file="+file );
				DocPrintUtil.println(con,"");
				logger.error("Read certificate failed.  reason="+e.getMessage()+" file="+file );
		  }
		
	}
	
	public static final void writeCertificate(StringBuffer con, URL url, String file ) {
		
        X509Certificate cert;
        byte[] derenccert = null;
		try {
		
			cert = CipherSuiteUtil.getServerCertificate(url);
			File f = new File(file);
			String path = f.getParentFile().getCanonicalPath();
			File dir = new File(path);
			
			if( dir.exists() ) {
				// Check permissions if file exists
				if(  !dir.canWrite() ) {
					DocPrintUtil.println(con,"Write certificate failed. reason=directory WRITE required.  dir="+path );
					DocPrintUtil.println(con,"");
					return;
				}
			} else {
				// Create the folder if it does not exist
				dir.mkdirs();
			}
		    // Write the file
			FileOutputStream out = new FileOutputStream(f);
			try {
				 Base64.Encoder encoder = Base64.getEncoder();
				 String cert_begin = "-----BEGIN CERTIFICATE-----\n";
				 String end_cert = "\n-----END CERTIFICATE-----";
				 derenccert = cert.getEncoded();
				 String pemB64 = new String(encoder.encode(derenccert));
				 StringBuffer pemBuff = new StringBuffer(pemB64.length());
				 int ct = 0;
				 for( int i=0; i< pemB64.length(); i++ ) {
					 ct++;
					 pemBuff.append(pemB64.charAt(i));
					 // Wrap line after 65-bytes. Looks better.
					 if ( (ct % 64) == 0 ) {
						 pemBuff.append(EOL);
						 ct=0;
					 }
				 }
				 String pemCert = cert_begin + pemBuff.toString() + end_cert;
				 out.write(pemCert.getBytes()); // PEM encoded certificate
			} catch(IOException e) {
				DocPrintUtil.println(con,"Write certificate failed.  reason="+e.getMessage()+" file="+file );
				DocPrintUtil.println(con,"");
				logger.error("Write certificate failed.  reason="+e.getMessage()+" file="+file );
				return;
			} finally {
				try { out.close(); } catch(IOException e1) {}	
			}

		} catch (SSLHandshakeException e ) {
			if( e.getMessage().indexOf("PKIX") > 0 ) {
				DocPrintUtil.println(con,"Certificate chain failed validation." );
				DocPrintUtil.println(con,"");
				logger.error("Certificate chain failed validation. err="+e.getMessage(),e );
			}else{
				DocPrintUtil.println(con,"SSLHandshakeException. err="+e.getMessage() );
				DocPrintUtil.println(con,"");
				logger.error("SSLHandshakeException. err="+e.getMessage(),e );
			}  	
			return;
		} catch (Exception e1) {
			DocPrintUtil.println(con,"Problem fetching certificate. err="+e1.getMessage() );
			DocPrintUtil.println(con,"");
			logger.error ("Problem fetching certificate. err="+e1.getMessage(), e1 );
			return;
		}
		
		long sz = (derenccert!=null) ? derenccert.length : 0;
		DocPrintUtil.println(con,"Certificate written successfully, bytes="+sz+" file="+file );
		DocPrintUtil.println(con,"");

	}
	
	//TODO: The utility of this method is that we don't have the URL of the server
	// that this certificate came from.  Scenario is we read from file.  To check trust
	// we need a connection to the server.  Here we try to create a host based upon
	// some assumptions.  If we could check trust without the signing algorithm in
	// checkTrustedCertificate( X509Certificate[] certs, URL url) then all this URL finding
	// could be elimated.  Need to look into this more.  All this is only a best effort to
	// establish the trust relationship while offline (e.g., --serverurl not specified).
	public static final void printTrustState(StringBuffer con, X509Certificate cert ) {
		
		String subjectDN = cert.getSubjectDN().getName();
		
		// Should not happen unless certificate is malformed.
		if( subjectDN.length() < 0 ) {
			DocPrintUtil.println(con, "Trusted State= >>>UNKNOWN<<<");
			logger.error("Can't form url.  reason=DN missing.");
			return;
		}
		
		String CN = "CN=";
		int start = subjectDN.indexOf(CN);
		int end = subjectDN.indexOf(' ',start)-1;
		
		// CN was found but trailing space was not then assume EOL follows CN.
		if( start>0 && end<0 ) {
		
			end = subjectDN.length();
		
	    // CN not found
		} else if( start<0 ) {
					
            DocPrintUtil.println(con, "Trusted State= >>>UNKNOWN<<<");
			logger.error("Can't form url.  reason=CN format error. subjectDN="+subjectDN.toString()+" s="+start+" e="+end);
			return;
			
		}
		
	    // Pull host from DN (if present) and wrap with https://host/
		// Abort on string processing errors and mark unknown state.
		URL url = null;
		String host = null;
		String surl = null;
		try {
			String WC = "*.";
			int s2 = subjectDN.lastIndexOf(WC);
			if( s2>0 ) { // Prune wildcards, if present, like CN=*.host.com to host.com
				host = subjectDN.substring(s2+WC.length(),end);
			} else { // Prune wildcards, if present, like CN=www.host.com to www.host.com
				host = subjectDN.substring(start+CN.length(),end);
			}
			surl = "https://"+host+"/";
			url = new URL(surl); 
			
		//Sink all exceptions and mark trust state unknown if problems.	
		} catch( Exception e ) {
            DocPrintUtil.println(con, "Trusted State= >>>UNKNOWN<<<");
			logger.error("Can't form url.  reason="+e.getMessage()+" surl="+surl+" s="+start+" e="+end);
			return;
		}
		
		printTrustState( con, url);
		
	}
	
	public static final void printTrustState(StringBuffer con, URL url ) {
		
        X509Certificate cert;
        X509Certificate[] certs;
		try {
		
			cert = CipherSuiteUtil.getServerCertificate(url);
			certs = CipherSuiteUtil.getServerCertificateChain(url);
		        	
		    boolean istrusted = CipherSuiteUtil.checkTrustedCertificate(certs,url);
		    String truststate = (istrusted) ?"TRUSTED" : ">>>NOT TRUSTED<<<";
            DocPrintUtil.println(con, "Trusted State="+truststate);

	      
		} catch (UnknownHostException e ) {
			
            DocPrintUtil.println(con, "Trusted State= >>>UNKNOWN<<<");
            
		} catch (SSLHandshakeException e ) {
			
			if( e.getMessage().indexOf("PKIX") > 0 ) {
				DocPrintUtil.println(con,"Certificate chain failed validation." );
				DocPrintUtil.println(con,"");
				logger.error("Certificate chain failed validation. err="+e.getMessage(),e );
			}else{
				DocPrintUtil.println(con,"SSLHandshakeException. err="+e.getMessage() );
				DocPrintUtil.println(con,"");
				logger.error("SSLHandshakeException. err="+e.getMessage(),e );
			}  	
        	
		} catch (Exception e1) {
			DocPrintUtil.println(con,"Problem fetching certificate. err="+e1.getMessage() );
			DocPrintUtil.println(con,"");
			logger.error ("Problem fetching certificate. err="+e1.getMessage(), e1 );
		}
		
	}
	
	/**
	 * Print security for the server certificate. 
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printServerCertificate(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con, "" );
		DocPrintUtil.println(con, "[Server certificate information]" );
	   
        X509Certificate cert;
//        X509Certificate[] certs;
		try {
		
			cert = CipherSuiteUtil.getServerCertificate(url);
//			certs = CipherSuiteUtil.getServerCertificateChain(url);
//		        	
//		    boolean istrusted = CipherSuiteUtil.checkTrustedCertificate(certs,url);
//		    String truststate = (istrusted) ?"TRUSTED" : ">>>NOT TRUSTED<<<";
//            DocPrintUtil.println(con, "Trusted State="+truststate);
			
		    printTrustState( con, url );
		
        	printX509Certificate( con, cert );

	        
//		} catch (SSLHandshakeException e ) {
//			
//			if( e.getMessage().indexOf("PKIX") > 0 ) {
//				DocPrintUtil.println(con,"Certificate chain failed validation." );
//				DocPrintUtil.println(con,"");
//				logger.error("Certificate chain failed validation. err="+e.getMessage(),e );
//			}else{
//				DocPrintUtil.println(con,"SSLHandshakeException. err="+e.getMessage() );
//				DocPrintUtil.println(con,"");
//				logger.error("SSLHandshakeException. err="+e.getMessage(),e );
//			}  	
        	
		} catch (Exception e1) {
			DocPrintUtil.println(con,"Problem fetching certificate. err="+e1.getMessage() );
			DocPrintUtil.println(con,"");
			logger.error ("Problem fetching certificate. err="+e1.getMessage(), e1 );
		}
	        
	}
	
	/**
	 * Print security for the server certificate chain.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	public static final void printServerCertificateChain( StringBuffer con, URL url ) {
		
		DocPrintUtil.println(con, "[Server certificate chain]" );
		
		StringBuffer buff = new StringBuffer();
		
		DocPrintUtil.println(con,"Chain Summary, end-entity --> root" );
		
        X509Certificate[] certs;
        
		try {
			certs = CipherSuiteUtil.getServerCertificateChain(url);
			
			boolean firstcert = true; 
			X509Certificate lastcert = null;
			String fingerprint = "";
			int n=0;
			
	        for (X509Certificate c : certs) {
        	 
				//fingerprint = CipherSuiteUtil.sha1Fingerprint(c.getEncoded());
	        	
				if( CipherSuiteUtil.isSelfSignedCertificate(c) ) {
					
					break;
				}
	        	
				DocPrintUtil.println(con,buff.toString()+"|" ); 
				DocPrintUtil.println(con,buff.toString()+"|" );
				
				StringBuffer attributes = new StringBuffer();
				
				attributes.append("NODE"+n+"(");
				
				if( firstcert ) {
					
					attributes.append("End-Entity ");
					
				} else {
					
					attributes.append("Intermediate CA ");
					
				}
				
				attributes.append(")--->");
				attributes.append("SubjectDN="+c.getSubjectDN().getName()+" IssuerDN="+c.getIssuerDN().getName());
				
	  		    //TODO: Signature algorithm is different than a digest algorithm.  Need to understand
	  		    // if parsing SHA256withRSA into SHA256 will work consistently.
				byte[] encx509 = c.getEncoded();
	        	String calgo = c.getSigAlgName();
	  		    String sa = calgo.substring(0,calgo.indexOf("with"));
	  		    attributes.append(", "+sa+"(Fingerprint)="+CipherSuiteUtil.signerFingerprint(encx509,sa));
				

				DocPrintUtil.println(con,buff.toString()+attributes.toString() );
				
				firstcert = false;
				lastcert = c;
				buff.append("   ");
				
				n++;
	
	        }
	        
			DocPrintUtil.println(con,buff.toString()+"|" ); 
			DocPrintUtil.println(con,buff.toString()+"|" );
			buff.append( "NODE"+n+"(");
	        
	        // At this point we have printed all certs returned by the server
	        // (via getServerCertificateChain()).  Note the server does NOT
			// return the root CA cert to us.  However, we can infer the
			// root by checking IssuerDN of the last Intermediate CA and
			// the AuthorityKeyIdentifier (if present).	         		
			if( CipherSuiteUtil.isJavaRootCertificateDN(lastcert.getIssuerDN().getName()) ) {
				
				buff.append("Java Root CA ");
				
			} else {
				
				buff.append("Self-Signed CA ");
				
			}
			
			buff.append(")--->");
			buff.append("SubjectDN="+lastcert.getIssuerDN().getName());
			
  		    //TODO: Signature algorithm is different than a digest algorithm.  Need to understand
  		    // if parsing SHA256withRSA into SHA256 will work consistently.
			byte[] encx509 = lastcert.getEncoded();
        	String calgo = lastcert.getSigAlgName();
  		    String sa = calgo.substring(0,calgo.indexOf("with"));
			buff.append(", "+sa+"(Fingerprint)="+CipherSuiteUtil.signerFingerprint(encx509,sa));
			
			DocPrintUtil.println(con,buff.toString() );

	        buff = new StringBuffer();

			DocPrintUtil.println(con,"" ); 
			DocPrintUtil.println(con, "[Chain details]" );
	        
			int n1=0;
	        for (X509Certificate c : certs) {
	        	
				DocPrintUtil.println(con,"[NODE"+n1+"] ");
				printX509Certificate(con,c);
				n1++;
				
	
	        }
	        
		} catch (SSLHandshakeException e ) {
			
			if( e.getMessage().indexOf("PKIX") > 0 ) {
				DocPrintUtil.println(con,"Certificate chain failed validation." );
				DocPrintUtil.println(con,"");
				logger.error("Certificate chain failed validation. err="+e.getMessage(),e );
			}else{
				DocPrintUtil.println(con,"SSLHandshakeException. err="+e.getMessage() );
				DocPrintUtil.println(con,"");
				logger.error("SSLHandshakeException. err="+e.getMessage(),e );
			}
				
		} catch (Exception e) {
			DocPrintUtil.println(con,"Problem fetching certificates. err="+e.getMessage() );
			DocPrintUtil.println(con,"");
			logger.error("Problem fetching certificates. err="+e.getMessage(),e );
		}
		
	
	}
	
	/**
	 * Print a X509Certificate.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	private static final void printX509Certificate( StringBuffer con, X509Certificate cert ) {

		logger.trace(cert.toString());
		
    	byte[] encx509;
		try {

			encx509 = cert.getEncoded();
        	try {
                
        		try {
                	
        			cert.checkValidity();
                    DocPrintUtil.println(con, "Validity Check=VALID, certificate valid between "+cert.getNotBefore().toString()+" and "+cert.getNotAfter().toString() );
                    
                } catch (CertificateNotYetValidException e) {
                    DocPrintUtil.println(con, "Validity Check= >>>NOT YET VALID<<<, certificate valid between "+cert.getNotBefore().toString()+" and "+cert.getNotAfter().toString() );
					//e.printStackTrace();
				}
            } catch(CertificateExpiredException c) {
                DocPrintUtil.println(con, "Validity Check= >>>EXPIRED<<<, certificate valid between "+cert.getNotBefore().toString()+" and "+cert.getNotAfter().toString() );
				//c.printStackTrace();
            }
        	
        	String calgo = cert.getSigAlgName();
        	
			DocPrintUtil.println(con, "SubjectDN="+cert.getSubjectDN() );
        	DocPrintUtil.println(con, "IssuerDN="+cert.getIssuerDN() );
        	DocPrintUtil.println(con, "Serial Number="+cert.getSerialNumber().toString() );     	
        	DocPrintUtil.println(con, "Signature Algorithm="+calgo);
        	DocPrintUtil.println(con, "Signature Algorithm OID="+cert.getSigAlgOID() );
        	DocPrintUtil.println(con, "Certificate Version ="+cert.getVersion() );
        	
        	try {
			
     		   //TODO: Signature algorithm is different than a digest algorithm.  Need to understand
     		   // if parsing SHA256withRSA into SHA256 will work consistently.
     		   String sa = calgo.substring(0,calgo.indexOf("with"));
        		
        		DocPrintUtil.println(con, sa+"(Fingerprint)="+CipherSuiteUtil.signerFingerprint(encx509,sa) );
//        		DocPrintUtil.println(con, "SHA1 Fingerprint="+CipherSuiteUtil.sha1Fingerprint(encx509) );
//        		DocPrintUtil.println(con, "MD5 Fingerprint="+CipherSuiteUtil.md5Fingerprint(encx509) );	
			
        	} catch (NoSuchAlgorithmException e) {
			
        		DocPrintUtil.println(con,"Problem generating certificate Fingerprints. err="+e.getMessage() );
				DocPrintUtil.println(con,"");
        		logger.error( "Problem generating Fingerprints. err="+e.getMessage(), e);
			
        	}
        	
    		DocPrintUtil.println(con, "Non-critical OIDs" );
        	
    		printNonCritOIDs( con, cert);
        	
    		DocPrintUtil.println(con, "Critical OIDs" );
        	
    		printCritOIDs( con, cert);     	
        	
        	DocPrintUtil.println(con, "" );
			
		} catch (CertificateEncodingException e) {
			DocPrintUtil.println(con,"Certificate encoding problem err="+e.getMessage() );
			logger.error( "Certificate encoding problem err="+e.getMessage(), e);
		}
		
	}
	
	/**
	 * Print a list of non-critical OIDs.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	private static final void printNonCritOIDs(StringBuffer con, X509Certificate cert ) {
		
    	Set<String> oids = cert.getNonCriticalExtensionOIDs();
    	
    	if( oids == null) {
			DocPrintUtil.println(con,"<None>");
			return;
    	}
    	
    	printOIDs( con, cert, oids );
		
	}
	
	/**
	 * Print a list of critical OIDs.
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 */
	private static final void printCritOIDs(StringBuffer con, X509Certificate cert) {
		
    	Set<String> oids = cert.getCriticalExtensionOIDs();
    	
    	if( oids == null) {
			DocPrintUtil.println(con,"<None>");
			return;
    	}
    	
    	printOIDs( con, cert, oids );
		
	}
	
	/**
	 * Print a Set of OIDs
	 * @param con StringBuffer for the output report.
	 * @param url Target URL of assessment.
	 * @param OIDs OIDs to print.
	 */
	private static final void printOIDs(StringBuffer con, X509Certificate cert, Set<String> OIDs) {
		
    	StringBuffer oidbuff = new StringBuffer();
    	
    	Iterator i2 = OIDs.iterator();
    	
    	while( i2.hasNext() ) {
    		
    		String oid = (String)i2.next();
    		
    		oidbuff.setLength(0);
    		
    		// it's either bend the rules or use bouncy castle
    		String aval = "<UNSUPPORTED>";
    		
    		try {
    			aval = CipherSuiteUtil.getExtensionValue(cert,oid);
    		} catch( IOException e ) {
    			logger.error("Can't print ASN.1 value", e);
    		}

    		oidbuff.append( "  -");
    		oidbuff.append( CipherSuiteUtil.getOIDKeyName(oid) );
    		oidbuff.append( '(' );
    		oidbuff.append( oid );
    		oidbuff.append( ") = " );
    		oidbuff.append( aval );
    		
    		DocPrintUtil.println(con, oidbuff.toString() );
    		
    		
    	}
		
	}
	
	/**
	 * Output a single line of text to buffer with line feed.
	 * @param con StringBuffer for the output report.
	 * @param text
	 */
	private static final void println( StringBuffer con, String text ) {
		
		con.append(text);
		con.append(EOL);
		
		logger.info(text);
				
	}

	/**
	 * Output a single line of text to buffer with no line feed.
	 * @param con StringBuffer for the output report.
	 * @param text
	 */
//	private static final void print( StringBuffer con, String text ) {
//		
//		con.append( text );
//				
//	}
	
}
