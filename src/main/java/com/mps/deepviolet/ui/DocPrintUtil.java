package com.mps.deepviolet.ui;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyledDocument;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.suite.CipherSuiteUtil;
import com.mps.deepviolet.suite.Protocol;

public class DocPrintUtil {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.ui.DocPrintUtil");
	
	public static final void printReportHeader( StringBuffer con, URL url ) {
		
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Report Run Information]");
		DocPrintUtil.println(con,"DeepViolet V0.1");
		Date d = new Date();
		DocPrintUtil.println(con,"Report generated on "+d.toString());
		DocPrintUtil.println(con,"Target url "+url.toString());	
		
	}
	
	public static final void printHostInformation(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Host information]");

        try {
        	InetAddress[] addresses = InetAddress.getAllByName(url.getHost());

	        for (InetAddress address : addresses ) {
	        	
	            try { 
	            	DocPrintUtil.print(con, "host="+address.getHostName()+" ["+address.getHostAddress()+"], " );
	            	DocPrintUtil.print(con, "canonical="+address.getCanonicalHostName());
	            	DocPrintUtil.println(con, "" );
		        } catch( Exception e ){
		        	DocPrintUtil.println(con,"skipping host, err="+e.getMessage());
		        	DocPrintUtil.println(con, "" );
		        	logger.warn("Skipping host. err="+e.getMessage(),e);
		        }     
	       
	        }
	        
		} catch (UnknownHostException e) {
        	DocPrintUtil.println(con,"Can't fetch host. err="+e.getMessage() );
        	logger.error("Can't fetch host. err="+e.getMessage(),e);
		}
	
	}
	
	public static final void printSupportedCipherSuites(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con,"");
		DocPrintUtil.println(con,"[Host supported server cipher suites]");
		
		
		try {
		
			String[] server_ciphers = CipherSuiteUtil.getServerSupportedCiphersuites(url);
				
				Protocol[] protocols = CipherSuiteUtil.getClientSupportedProtocols();
				
				for ( Protocol protocol : protocols ) {
					
					String p = protocol.getName();
					
					DocPrintUtil.println(con,p);
					
				    for ( String cipher : server_ciphers ) {
				    	
				    	if ( protocol.hasCipher(cipher) ) {
				    		
				    		String strength = CipherSuiteUtil.getStrength(cipher);
				    		
							DocPrintUtil.print(con,"  - (SUPPORTED) ");
							DocPrintUtil.print(con,cipher);
							DocPrintUtil.print(con," (STRENGTH=");
							DocPrintUtil.print(con,strength);
							DocPrintUtil.println(con," )");
		
				    	}
				    	
				    }
				   		
				}
		
		} catch (Exception e) {
        	DocPrintUtil.println(con,"Problem processing server ciphers. err="+e.getMessage() );
        	logger.error("Problem processing server ciphers. err="+e.getMessage(),e);
		}

			
	}
	
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
			logger.error( "Problem getting connection information. err="+e.getMessage(), e);
		} catch (IOException e) {
			DocPrintUtil.println(con,"I\\O problem reading socket. err="+e.getMessage() );
			logger.error( "I\\O problem reading socket. err="+e.getMessage(), e);
		}  		
	}
	
	
	public static final void printServerCertificate(StringBuffer con, URL url) {
		
		DocPrintUtil.println(con, "" );
		DocPrintUtil.println(con, "[Server certificate information]" );
	   
        X509Certificate cert;
        X509Certificate[] certs;
		try {
		
			cert = CipherSuiteUtil.getServerCertificate(url);
			certs = CipherSuiteUtil.getServerCertificateChain(url);
		        	
		    boolean istrusted = CipherSuiteUtil.checkTrustedCertificate(certs,url);
		    String truststate = (istrusted) ?"TRUSTED" : "NOT TRUSTED";
		    
            DocPrintUtil.println(con, "Trusted Status="+truststate);
            
//            String ocspstatus = CipherSuiteUtil.checkOCSPStatus( cert, certs[1]);
//            
//            DocPrintUtil.println(doc, "OCSP Status="+ocspstatus,regular);
			
        	printX509Certificate( con, cert );

	        
		} catch (Exception e1) {
			DocPrintUtil.println(con,"Problem fetching certificate. err="+e1.getMessage() );
			logger.error ("Problem fetching certificate. err="+e1.getMessage(), e1 );
		}
	        
	}
	
	public static final void printServerCertificateChain( StringBuffer con, URL url ) {
		
		DocPrintUtil.println(con, "[Server certificate chain]" );
		
		StringBuffer buff = new StringBuffer();
		
		DocPrintUtil.println(con,"Chain summary" );
		
        X509Certificate[] certs;
        
		try {
			certs = CipherSuiteUtil.getServerCertificateChain(url);
			
			int i=0; boolean selfsigned = false;
			
	        for (X509Certificate c : certs) {
        	 
	        	// print server cert and intermediary CAs
				DocPrintUtil.println(con,buff.toString()+"|" ); 
				DocPrintUtil.println(con,buff.toString()+"|" ); 
				if( i==0 ) {
					DocPrintUtil.println(con,buff.toString()+"End-Enity Certificate--->"+ c.getSubjectDN() );  
				} else {
					if( !CipherSuiteUtil.isSelfSignedCertificate(c ) ) {
						DocPrintUtil.println(con,buff.toString()+"Intermediate CA--->"+ c.getSubjectDN() );
					} else {
						DocPrintUtil.println(con,buff.toString()+"Self-Signed Root--->"+ c.getSubjectDN() );
						selfsigned=true;
						break;
					}
				}
				
				i++;
				buff.append("   ");
	
	        }
	        // Print root cert unless it's self-signed then there is no Java root.
	        if( !selfsigned ) {
				buff.append("   ");
		        String lca = certs[certs.length-1].getIssuerDN().getName();
		        DocPrintUtil.println(con,buff.toString()+"|" ); 
				DocPrintUtil.println(con,buff.toString()+"|" ); 
				DocPrintUtil.println(con,buff.toString()+"Root CA(Java CACERTS)--->"+ lca );  
	        }


	        buff = new StringBuffer();

			DocPrintUtil.println(con,"" ); 
			DocPrintUtil.println(con, "Chain details" );
	        
	        for (X509Certificate c : certs) {
	        	 
				printX509Certificate(con,c);
				
	
	        }
	        
		} catch (Exception e1) {
			DocPrintUtil.println(con,"Problem fetching certificates. err="+e1.getMessage() );
			logger.error("Problem fetching certificates. err="+e1.getMessage(),e1 );
		}
		
	
	}
	
	private static final void printX509Certificate( StringBuffer con, X509Certificate cert ) {

		logger.trace(cert.toString());
		
    	byte[] encx509;
		try {

			encx509 = cert.getEncoded();
        	try {
                
        		try {
                	
        			cert.checkValidity();
                    DocPrintUtil.println(con, "Validity Status= VALID.  Certificate valid between "+cert.getNotBefore().toString()+" and "+cert.getNotAfter().toString() );
                    
                } catch (CertificateNotYetValidException e) {
                    DocPrintUtil.println(con, "Validiy Status= INVALID.  Certificate valid between "+cert.getNotBefore().toString()+" and "+cert.getNotAfter().toString() );
					e.printStackTrace();
				}
            } catch(CertificateExpiredException c) {
                DocPrintUtil.println(con, "Validiy Status= INVALID. Certificate valid between "+cert.getNotBefore().toString()+" and "+cert.getNotAfter().toString() );
				c.printStackTrace();
            }
			DocPrintUtil.println(con, "SubjectDN="+cert.getSubjectDN() );
        	DocPrintUtil.println(con, "IssuerDN="+cert.getIssuerDN() );
        	DocPrintUtil.println(con, "Serial Number="+cert.getSerialNumber().toString() );     	
        	DocPrintUtil.println(con, "Signature Algorithm="+cert.getSigAlgName() );
        	DocPrintUtil.println(con, "Signature Algorithm OID="+cert.getSigAlgOID() );
        	DocPrintUtil.println(con, "Certificate Version ="+cert.getVersion() );
        	
        	try {
			
        		DocPrintUtil.println(con, "SHA1 Fingerprint="+CipherSuiteUtil.sha1Fingerprint(encx509) );
			
        	} catch (NoSuchAlgorithmException e) {
			
        		DocPrintUtil.println(con,"Problem generating certificate SHA1 fingerprint. err="+e.getMessage() );
        		logger.error( "Problem generating certificate SHA1 fingerprint. err="+e.getMessage(), e);
			
        	}
        	try {
    			
        		DocPrintUtil.println(con, "MD5 Fingerprint="+CipherSuiteUtil.md5Fingerprint(encx509) );
			
        	} catch (NoSuchAlgorithmException e) {
			
        		DocPrintUtil.println(con,"Problem generating certificate MD5 fingerprint. err="+e.getMessage() );
				logger.error("Problem generating certificate MD5 fingerprint. err="+e.getMessage(),e );
			
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
	
	private static final void printNonCritOIDs(StringBuffer con, X509Certificate cert ) {
		
    	Set<String> oids = cert.getNonCriticalExtensionOIDs();
    	
    	printOIDs( con, cert, oids );
		
	}
	
	private static final void printCritOIDs(StringBuffer con, X509Certificate cert) {
		
    	Set<String> oids = cert.getCriticalExtensionOIDs();
    	
    	printOIDs( con, cert, oids );
		
	}
	
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
    			logger.error("Can't print ANS.1 value", e);
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
	
	private static final void println( StringBuffer con, String text ) {
		
		con.append( text );
		con.append('\n');
		
		logger.info(text);
				
	}
	
	private static final void print( StringBuffer con, String text ) {
		
		con.append( text );
				
	}
	
}
