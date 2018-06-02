package com.mps.deepviolet.api;

import java.io.IOException;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import javax.net.ssl.SSLHandshakeException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of IDVX509Certificate specification
 * @author Milton Smith
 * @see com.mps.deepviolet.api.IDVX509Certificate
 */
class DVX509Certificate implements IDVX509Certificate {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.DVX509Certificate");
	private final String EOL = System.getProperty("line.separator");
	
	private X509Certificate cert;
	private X509Certificate[] chain;
	private DVX509Certificate[] dvChain;
	private IDVEng eng;
	
	private String signingAlgorithm;
	private String signingAlgorithmOID;
	private BigInteger certificateSerialNumber;
	private int iCertificateVersion;
	private String notValidBefore;
	private String notValidAfter;
	private ValidState iValidityState;
	private String subjectDN;
	private String issuerDN;
	private TrustState iTrustState;
	private boolean bSelfSignedCertificate;
	private boolean bJavaRootCertificate;
	private String certificateFingerPrint;

	private HashMap<String,String> nonCritOidMap = new HashMap<String,String>();
	private HashMap<String,String> critOidMap = new HashMap<String,String>();
	
	/**
	 * CTOR
	 * @param cert X509Certificate to initialize
	 * @throws DVException Thrown on trouble
	 */
	DVX509Certificate( IDVEng eng, X509Certificate cert ) throws DVException {
		try {
			this.cert = cert;
			this.eng = eng;
			
			signingAlgorithm = cert.getSigAlgName();
			notValidBefore = cert.getNotBefore().toString();
			notValidAfter = cert.getNotAfter().toString();
			certificateSerialNumber = cert.getSerialNumber();
			subjectDN = cert.getSubjectDN().toString();
			issuerDN = cert.getIssuerDN().toString();
			signingAlgorithmOID = cert.getSigAlgOID();
			iCertificateVersion = cert.getVersion();
			iTrustState = TrustState.UNKNOWN; //default
			
			//TODO: Signature algorithm is different than a digest algorithm.  Need to understand
			//      if parsing SHA256withRSA into SHA256 will work consistently.
			byte[] encx509 = cert.getEncoded();
			String sa = signingAlgorithm.substring(0,signingAlgorithm.indexOf("with")); 
			certificateFingerPrint = CipherSuiteUtil.signerFingerprint(encx509,sa);
			
			//Check certificate validity, start < now < expiration.
        	try {
        		try {
        			cert.checkValidity();
        			iValidityState = ValidState.VALID;
                } catch (CertificateNotYetValidException e) {
                	iValidityState = ValidState.NOT_YET_VALID;
				}
            } catch(CertificateExpiredException c) {
            	iValidityState = ValidState.EXPIRED;
            }
	
			// Gather non-critical OIDs
	    	Set<String> oids = cert.getNonCriticalExtensionOIDs();
			if (oids != null) {
                assignOIDs(nonCritOidMap,oids);
            }

			// Gather critical OIDs
	    	oids = cert.getCriticalExtensionOIDs();
			if (oids != null) {
                assignOIDs(critOidMap,oids);
            }

			// Self-signed or not.
	    	bSelfSignedCertificate = CipherSuiteUtil.isSelfSignedCertificate(cert);
			
	        // At this point we have printed all certs returned by the server
	        // (via getServerCertificateChain()).  Note the server does NOT
			// return the root CA cert to us.  However, we can infer the
			// root by checking IssuerDN of the last Intermediate CA and
			// the AuthorityKeyIdentifier (if present).	         		
	    	bJavaRootCertificate = CipherSuiteUtil.isJavaRootCertificateDN(cert.getIssuerDN().getName());			
	    	
	    	// Initialize online only activities.  Easy to override in child.
	    	onlineInitializationOnly();
	    	
		} catch( Exception e ) {
			throw new DVException(e);
		}	
		
	}

    /**
     * Convience method to allow initialization of some features we don't want to
     * execute in offline version.  Allows subclasses to easily override and
     * block execution of these features.
     * @throws DVException Thrown on problems.
     */
	void onlineInitializationOnly() throws DVException{
    	
    	// Assign cert chain
    	assignCertificateChain();
		
    	// Assign the trust state, trusted, untrusted, unknown to the cert
    	assignTrustState();
	
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getSigningAlgorithm()
	 */
	public String getSigningAlgorithm() {
		return signingAlgorithm;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCertificateSerialNumber()
	 */
	public BigInteger getCertificateSerialNumber() {
		return certificateSerialNumber;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getSigningAlgorithmOID()
	 */
	public String getSigningAlgorithmOID(){
		return signingAlgorithmOID;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCertificateVersion()
	 */
	public int getCertificateVersion(){
		return iCertificateVersion;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNotValidBefore()
	 */
	public String getNotValidBefore(){
		return notValidBefore;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNotValidAfter()
	 */
	public String getNotValidAfter(){
		return notValidAfter;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getValidityState()
	 */
	public ValidState getValidityState(){
		return iValidityState;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getSubjectDN()
	 */
	public String getSubjectDN(){
		return subjectDN;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getIssuerDN()
	 */
	public String getIssuerDN(){
		return issuerDN;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getTrustState()
	 */
	public TrustState getTrustState(){
		return iTrustState;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.isSelfSignedCertificate()
	 */
	public boolean isSelfSignedCertificate(){
		return bSelfSignedCertificate;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.isJavaRootCertificate()
	 */
	public boolean isJavaRootCertificate(){
		return bJavaRootCertificate;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCertificateFingerPrint()
	 */
	public String getCertificateFingerPrint(){
		return certificateFingerPrint;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNonCritOIDProperties()
	 */
	public String[] getNonCritOIDProperties() {
		Set<String> oids = nonCritOidMap.keySet();
		return oids.toArray(new String[0]);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getNonCritPropertyValue(String)
	 */
	public String getNonCritPropertyValue(String key) {
		if( key==null || !nonCritOidMap.containsKey(key) ) return null;
		return nonCritOidMap.get(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCritPropertyValue()
	 */
	public String[] getCritOIDProperties() {
		Set<String> oids = critOidMap.keySet();
		return oids.toArray(new String[0]);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCritPropertyValue(String)
	 */
	public String getCritPropertyValue(String key) {
		if( key==null || !critOidMap.containsKey(key) ) return null;
		return critOidMap.get(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.isContainsNonCritPropertyKey()
	 */
	public boolean isContainsNonCritPropertyKey(String key) {
		return nonCritOidMap.containsKey(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.isContainsCritPropertyKey()
	 */
	public boolean isContainsCritPropertyKey(String key) {
		return critOidMap.containsKey(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.getCertificateChain()
	 */
	public synchronized IDVX509Certificate[] getCertificateChain() throws DVException {
		
		if( dvChain != null ) return dvChain;
		ArrayList<DVX509Certificate> list = new ArrayList<DVX509Certificate>();
		for (X509Certificate lcert : chain ) {
			list.add(new DVX509Certificate(eng, lcert));
		}
		dvChain = list.toArray(new DVX509Certificate[0]);
		return dvChain;
	}
	
	/**
	 * Assign OIDs to the key/value store.
	 * @param lmap Map to insert OIDs
	 * @param OIDs Set of OIDs to assign.
	 */
	private void assignOIDs(HashMap<String, String> lmap, Set<String> OIDs) {
		for (String oid : OIDs) {
			//TODO unsupported oids should be found in logs and improved over time.
			String value = UNSUPPORTED_OID;
			try {
				value = CipherSuiteUtil.getExtensionValue(cert, oid);
			} catch (IOException e) {
				logger.error("Can't print ASN.1 value", e);
			}
			lmap.put(CipherSuiteUtil.getOIDKeyName(oid), value);
		}
	}

	/**
	 * Assign the certificate chain to this certificate.
	 * @throws DVException Thrown on problems
	 */
	private void assignCertificateChain() throws DVException {
			try {
				chain = CipherSuiteUtil.getServerCertificateChain(eng.getDVSession().getURL());
			} catch (SSLHandshakeException e ) {
				if( e.getMessage().indexOf("PKIX") > 0 ) {
					String msg = "Certificate chain failed validation. err=" + e.getMessage();
					logger.error(msg,e);
					throw new DVException(msg,e);
				}else{
					String msg = "SSLHandshakeException. err=" + e.getMessage();
					logger.error(msg,e);
					throw new DVException(msg,e);
				}
					
			} catch (Exception e) {
				String msg = "Problem fetching certificates. err=" + e.getMessage();
				logger.error(msg,e);
				throw new DVException(msg,e);
			}
			
	}
	
	/**
	 * The utility of this method is that we don't have the URL of the server
	 * that this certificate came from.  Scenario is we read from file.  To check trust
	 * we need a connection to the server.  Here we try to create a host based upon
	 * some assumptions.  If we could check trust without the signing algorithm in
	 * checkTrustedCertificate( X509Certificate[] certs, URL url) then all this URL finding
	 * could be eliminated. Need to look into this more.  All this is only a best effort to
	 * establish the trust relationship while offline (e.g., --serverurl not specified).
	 */
    private void assignTrustState() throws DVException {
		try {
			//todo should look at a differnt way to do this later
			boolean bTrusted = CipherSuiteUtil.checkTrustedCertificate( chain, eng.getDVSession().getURL() );
			if( bTrusted ) {
				iTrustState = TrustState.TRUSTED;
			} else {
				iTrustState = TrustState.UNTRUSTED;
			}
		} catch( KeyStoreException e ) {
			iTrustState = TrustState.UNKNOWN;
			throw new DVException("Problem accessing keystore, err=" + e.getMessage(),e);
		} catch( NoSuchAlgorithmException e ) {
			iTrustState = TrustState.UNKNOWN;
			throw new DVException("No ciphersuite available, err=" + e.getMessage(),e);
		} catch( UnknownHostException e ) {
			iTrustState = TrustState.UNKNOWN;
			throw new DVException("Unknown host, err=" + e.getMessage(),e);
		} catch( IOException e ) {
			throw new DVException("File system problem, err=" + e.getMessage(),e);
		}
	}		

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.toString()
	 */
	public String toString() {
		
		StringBuilder buff = new StringBuilder();
		
		buff.append(super.toString());
		buff.append(EOL);
		
		buff.append("SUBJECTDN");
		buff.append('=');
		buff.append(subjectDN);
		buff.append(EOL);
		
		buff.append("SIGNING_ALGORITHM");
		buff.append('=');
		buff.append(signingAlgorithm);
		buff.append(EOL);
		
		buff.append("CERTIFICATE_FINGERPRINT");
		buff.append('=');
		buff.append(certificateFingerPrint);
		buff.append(EOL);
		
		buff.append("ISSUERDN");
		buff.append('=');
		buff.append(issuerDN);
		buff.append(EOL);
		
		buff.append("VALIDITY_STATE");
		buff.append('=');
		String state = "<ERROR>";
		if( iValidityState == ValidState.EXPIRED ) {
			state = "EXPIRED";
		} else if ( iValidityState == ValidState.VALID ) {
			state = "VALID";
		} else if ( iValidityState == ValidState.NOT_YET_VALID ) {
			state = "NOT_YET_VALID";
		} 
		buff.append(state);
		buff.append(EOL);
		
		buff.append("TRUST_STATE");
		buff.append('=');
		state = "<ERROR>";
		if( iTrustState == TrustState.TRUSTED ) {
			state = "TRUSTED";
		} else if ( iTrustState == TrustState.UNKNOWN ) {
			state = "UNKNOWN";
		} else if ( iTrustState == TrustState.UNTRUSTED ) {
			state = "UNTRUSTED";
		} 
		buff.append(state);
		buff.append(EOL);
		
		buff.append("VALIDITY_NOT_VALID_BEFORE");
		buff.append('=');
		buff.append(notValidBefore);
		buff.append(EOL);
		
		buff.append("VALIDITY_NOT_VALID_AFTER");
		buff.append('=');
		buff.append(notValidAfter);
		buff.append(EOL);
		
		buff.append("CERTIFICATE_SERIAL_NUMBER");
		buff.append('=');
		buff.append(certificateSerialNumber);
		buff.append(EOL);
		
		buff.append("CERTIFICATE_VERSION");
		buff.append('=');
		buff.append(Integer.toString(iCertificateVersion));
		buff.append(EOL);
		
		
		buff.append("SELF_SIGNED_CERTIFICATE");
		buff.append('=');
		buff.append(Boolean.toString(bSelfSignedCertificate));
		buff.append(EOL);
		
		buff.append("JAVA_ROOT_CERTIFICATE");
		buff.append('=');
		buff.append(Boolean.toString(bJavaRootCertificate));
		buff.append(EOL);
		
		buff.append("SIGNING_ALGORITHM_OID");
		buff.append('=');
		buff.append(signingAlgorithmOID);
		buff.append(EOL);
		
		// Non-crit-OIDs
		buff.append("CRIT_OIDS[");
		boolean fi = true;
		for (String key : critOidMap.keySet()) {
			String value = critOidMap.get(key);
			if(!fi) {
			    buff.append(", ");
            }
			buff.append(key);
			buff.append('=');
			buff.append(value);
			fi=false;
		}
		buff.append("]");
		buff.append(EOL);
		
		// Non-crit-OIDs
		buff.append("NON_CRIT_OIDS[");
		fi = true;
		for (String key : nonCritOidMap.keySet()) {
			String value = nonCritOidMap.get(key);
			if(!fi) buff.append(", ");
			buff.append(key);
			buff.append('=');
			buff.append(value);
			fi=false;
		}
		buff.append("]");
		buff.append(EOL);
		
		return buff.toString();
	}
	

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IDVX509Certificate.equals(Object)
	 */
	public boolean equals( Object obj ) {
		
		boolean o1=false;
		boolean o2=false;
		boolean o3=false;
		boolean o4=false;
		boolean o5=false;
		boolean o6=false;
		boolean o7=false;
		boolean o8=false;
		boolean o9=false;
		boolean o10=false;
		boolean o11=false;
		boolean o12=false;
		boolean o13=false;
		boolean o14=false;
		boolean o15=false;
		
		if( obj != null ) {
			if( obj instanceof IDVX509Certificate ) {
				IDVX509Certificate c = (IDVX509Certificate)obj;

				o1 = signingAlgorithm.equals(c.getSigningAlgorithm());	
				o2 = signingAlgorithmOID.equals(c.getSigningAlgorithmOID());	
				o3 = iCertificateVersion == c.getCertificateVersion();	
				o4 = notValidBefore.equals(c.getNotValidBefore());
				o5 = notValidAfter.equals(c.getNotValidAfter());
				o6 = iValidityState == c.getValidityState();	
				o7 = subjectDN.equals(c.getSubjectDN());
				o8 = issuerDN.equals(c.getIssuerDN());
				o9 = iTrustState == c.getTrustState();
				o10 = bSelfSignedCertificate;
				o11 = bJavaRootCertificate;
				o12 = certificateFingerPrint.equals(c.getCertificateFingerPrint());
				
				o13 = true;
				for(String key : nonCritOidMap.keySet()) {
					if( c.isContainsNonCritPropertyKey(key) ) {
						o13 = false;
                        break;
					}
				}
				
				o14 = true;
				for(String key : critOidMap.keySet()) {
                    if (c.isContainsCritPropertyKey(key)) {
                        o14 = false;
                        break;
                    }
                }
				
				o15 = certificateSerialNumber.equals(c.getCertificateSerialNumber());
				
			}
		}
		return (o1 && o2  && o3  && o4  && o5  && o6  && o7  && o8  && o9  && o10  && o11  && o12  && o13  && o14 && o15);
	}
	
}
