package com.mps.deepviolet.api;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLHandshakeException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.suite.CipherSuiteUtil;
import com.mps.deepviolet.suite.ServerMetadata;

/**
 * Utility class to access DeepViolet SSL/TLS features from API
 * @author Milton Smith
 */
class DVEng implements IDVEng {
	
	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.DVEng");
	
	private static final int VERSION_MAJOR = 1;
	private static final int VERSION_MINOR = 5;
	private static final int VERSION_BUILD = 2;
	private static final String VERSION_STRING = "V"+VERSION_MAJOR+"."+VERSION_MINOR+"."+VERSION_BUILD;
	
	private final String EOL = System.getProperty("line.separator");
	
	private IDVSession session;
//    private DVPrint dvPrint;
	
	/* (non-Javadoc)
	 */
	DVEng( IDVSession session ) {
		this.session = session;
	}

//	/* (non-Javadoc)
//	 * @see com.mps.deepviolet.api.IDVEng#getDVOffPrint()
//	 */
//	public IDVOffPrint getDVOffPrint() throws DVException {
//		return new DVOffPrint(this, new StringBuffer());
//	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDVOnPrint()
	 */
//	public IDVPrint getDVPrint() throws DVException {
//		return getDVPrint(new StringBuffer(2500));
//	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDVOnPrint()
	 */
//	public IDVPrint getDVPrint( StringBuffer con) throws DVException {
//		return new DVPrint(this, con);
//	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDVSession()
	 */
	public IDVSession getDVSession() {
		return session;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDeepVioletMajorVersion()
	 */
	public final int getDeepVioletMajorVersion() {
		return VERSION_MAJOR;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDeepVioletMinorVersion()
	 */
	public final int getDeepVioletMinorVersion() {
		return VERSION_MINOR;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDeepVioletBuildVersion()
	 */
	public final int getDeepVioletBuildVersion() {
		return VERSION_BUILD;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getDeepVioletStringVersion()
	 */
	public final String getDeepVioletStringVersion() {
		return VERSION_STRING;
	}
 	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getCipherSuites()
	 */
	public final IDVCipherSuite[] getCipherSuites() throws DVException {
		List<IDVCipherSuite> list = new ArrayList<IDVCipherSuite>();
		URL url = session.getURL();
		try {
			Map<String,List<String>> allCiphers = new HashMap<String, List<String>>();
			ServerMetadata m = CipherSuiteUtil.getServerMetadataInstance( url );
			if( m == null ) {
				return null;
			}

			// TODO: Move protocol versions to own type
			if( m.containsKey("getServerMetadataInstance","SSLv2") ) allCiphers.put("SSLv2",m.getVectorValue("getServerMetadataInstance","SSLv2"));
			if( m.containsKey("getServerMetadataInstance","SSLv3") ) allCiphers.put("SSLv3",m.getVectorValue("getServerMetadataInstance","SSLv3"));
			if( m.containsKey("getServerMetadataInstance","TLSv1.0") ) allCiphers.put("TLSv1.0",m.getVectorValue("getServerMetadataInstance","TLSv1.0"));
			if( m.containsKey("getServerMetadataInstance","TLSv1.1") ) allCiphers.put("TLSv1.1",m.getVectorValue("getServerMetadataInstance","TLSv1.1"));
			if( m.containsKey("getServerMetadataInstance","TLSv1.2") ) allCiphers.put("TLSv1.2",m.getVectorValue("getServerMetadataInstance","TLSv1.2"));

            for( String tlsVersion : allCiphers.keySet()  ) {
				for(String cipher : allCiphers.get( tlsVersion )) {
					String ciphernameOnly = cipher;
					int idx = cipher.indexOf("(0x", 0);
					if( idx != -1 ) {
						ciphernameOnly = cipher.substring(0,idx);
					}

					// TODO: Strength evaluation should evaluate strength of connection and all used parameters, not only cipher
					String strength = "UNKNOWN";	
					if( ciphernameOnly.length() > 0 ) {
						strength = CipherSuiteUtil.getStrength(ciphernameOnly);
						if( cipher.startsWith(CipherSuiteUtil.NO_CIPHERS)) {
								strength = "";
						}
					}	
					MutableDVCipherSuite suite = new MutableDVCipherSuite(cipher,strength,tlsVersion);
					list.add(suite);
				}
			}
		} catch( Exception e ) {
			String msg = "Problem fetching ciphersuites. err="+e.getMessage();	
			logger.error(msg,e );
			throw new DVException(msg,e );
		}
		return (IDVCipherSuite[])list.toArray(new MutableDVCipherSuite[0]);	
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVEng#getCertificate()
	 */
	public final IDVX509Certificate getCertificate() throws DVException {
		X509Certificate cert;
		IDVX509Certificate dvCert;
		try {
			cert = CipherSuiteUtil.getServerCertificate(session.getURL());					
			dvCert = new DVX509Certificate(this,cert);
		} catch (Exception e) {
			String msg = "Problem fetching certificate. err="+e.getMessage();	
			logger.error(msg,e );
			throw new DVException(msg,e );
		}
		return dvCert;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVPrint#writeCertificate(java.lang.String)
	 */
	public final long writeCertificate( String file ) throws DVException {
        X509Certificate cert;
        byte[] derenccert = null;
		try {
			cert = CipherSuiteUtil.getServerCertificate(session.getURL());
			File f = new File(file);
			String path = f.getParentFile().getCanonicalPath();
			File dir = new File(path);
			if( dir.exists() ) {
				// Check permissions if file exists
				if(  !dir.canWrite() ) {
					DVException e = new DVException("Write certificate failed. reason=directory WRITE required.  dir="+path );
					throw e;
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
				DVException e1 = new DVException("Error writing file.  file="+f.getAbsolutePath(), e);
				throw e1;
			} finally {
				try { out.close(); } catch(IOException e1) {}	
			}
		} catch (SSLHandshakeException e ) {
			if( e.getMessage().indexOf("PKIX") > 0 ) {
				DVException e1 = new DVException("Certificate chain failed validation. err="+e.getMessage(),e );
				throw e1;
			} else {
				DVException e1 = new DVException("SSLHandshakeException. err="+e.getMessage(),e );
				throw e1;
			}  	
		} catch (Exception e) {
			DVException e1 = new DVException("SSLHandshakeException. err="+e.getMessage(),e);
			throw e1;
		}
		
		long sz = (derenccert!=null) ? derenccert.length : 0;
		return sz;
	}
}

