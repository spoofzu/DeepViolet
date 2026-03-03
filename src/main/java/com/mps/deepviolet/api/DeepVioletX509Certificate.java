package com.mps.deepviolet.api;

import java.io.IOException;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLHandshakeException;

import com.mps.deepviolet.util.ECCurveNames;
import com.mps.deepviolet.util.X509Extensions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of IX509Certificate specification
 * @author Milton Smith
 * @see com.mps.deepviolet.api.IX509Certificate
 */
class DeepVioletX509Certificate implements IX509Certificate {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.DeepVioletX509Certificate");
	private final String EOL = System.getProperty("line.separator");
	
	private X509Certificate cert;
	private X509Certificate[] chain;
	private DeepVioletX509Certificate[] dvChain;
	private IEngine eng;
	
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

	private String publicKeyAlgorithm;
	private int publicKeySize;
	private String publicKeyCurve;
	private long daysUntilExpiration;
	private RevocationStatus revocationStatus;
	private List<String> subjectAlternativeNames;

	private HashMap<String,String> nonCritOidMap = new HashMap<String,String>();
	private HashMap<String,String> critOidMap = new HashMap<String,String>();
	
	/**
	 * CTOR
	 * @param cert X509Certificate to initialize
	 * @throws DeepVioletException Thrown on trouble
	 */
	DeepVioletX509Certificate( IEngine eng, X509Certificate cert ) throws DeepVioletException {
		initializeOfflineData(eng, cert);

		// Initialize online only activities.  Easy to override in child.
		onlineInitializationOnly();
	}

	/**
	 * Package-private constructor for chain members.
	 * Does NOT make additional network calls - uses pre-fetched chain data.
	 * @param eng The engine
	 * @param cert The certificate to wrap
	 * @param preloadedChain The pre-fetched certificate chain
	 * @param chainIndex Index of this cert in the chain (0=end-entity)
	 */
	DeepVioletX509Certificate(IEngine eng, X509Certificate cert, X509Certificate[] preloadedChain, int chainIndex) throws DeepVioletException {
		initializeOfflineData(eng, cert);

		// Use preloaded chain instead of fetching
		this.chain = preloadedChain;

		// Chain members don't need their own dvChain (only root cert provides it)
		this.dvChain = null;

		// Assign trust state based on chain position
		assignTrustStateForChainMember(chainIndex);

		// Run revocation checks using the preloaded issuer cert
		assignRevocationStatusForChainMember(chainIndex);
	}

	/**
	 * Initialize all offline (non-network) certificate data.
	 */
	private void initializeOfflineData(IEngine eng, X509Certificate cert) throws DeepVioletException {
		try {
			this.cert = cert;
			this.eng = eng;

			signingAlgorithm = cert.getSigAlgName();
			notValidBefore = cert.getNotBefore().toString();
			notValidAfter = cert.getNotAfter().toString();
			certificateSerialNumber = cert.getSerialNumber();
			subjectDN = cert.getSubjectX500Principal().toString();
			issuerDN = cert.getIssuerX500Principal().toString();
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
	    	bJavaRootCertificate = CipherSuiteUtil.isJavaRootCertificateDN(cert.getIssuerX500Principal().getName());

	    	// Public key details
	    	java.security.PublicKey pubKey = cert.getPublicKey();
	    	publicKeyAlgorithm = pubKey.getAlgorithm();
	    	if (pubKey instanceof RSAPublicKey rsaKey) {
	    		publicKeySize = rsaKey.getModulus().bitLength();
	    	} else if (pubKey instanceof ECPublicKey ecKey) {
	    		ECParameterSpec ecSpec = ecKey.getParams();
	    		publicKeySize = ecSpec.getOrder().bitLength();
	    		// Try to find the curve name
	    		publicKeyCurve = lookupECCurveName(ecSpec);
	    	} else {
	    		// DSA or other
	    		publicKeySize = pubKey.getEncoded().length * 8;
	    	}

	    	// Days until expiration
	    	long diffMs = cert.getNotAfter().getTime() - System.currentTimeMillis();
	    	daysUntilExpiration = TimeUnit.MILLISECONDS.toDays(diffMs);

	    	// Subject Alternative Names
	    	subjectAlternativeNames = X509Extensions.getSubjectAlternativeNames(cert);

		} catch( Exception e ) {
			throw new DeepVioletException(e);
		}
	}

    /**
     * Convenience method to allow initialization of some features we don't want to
     * execute in offline version.  Allows subclasses to easily override and
     * block execution of these features.
     * @throws DeepVioletException Thrown on problems.
     */
	void onlineInitializationOnly() throws DeepVioletException{

    	// Assign cert chain (fetches X509Certificate[] from server)
    	assignCertificateChain();

    	// Eagerly build dvChain so getCertificateChain() doesn't make network calls
    	buildDvChainEagerly();

    	// Assign the trust state, trusted, untrusted, unknown to the cert
    	assignTrustState();

    	// Run revocation checks (needs issuer cert from chain)
    	assignRevocationStatus();
	}

	/**
	 * Eagerly build the dvChain array during initialization.
	 * This ensures getCertificateChain() is a pure getter with no network calls.
	 */
	private void buildDvChainEagerly() throws DeepVioletException {
		if (chain == null || chain.length == 0) {
			dvChain = new DeepVioletX509Certificate[0];
			return;
		}

		ArrayList<DeepVioletX509Certificate> list = new ArrayList<>();
		for (int i = 0; i < chain.length; i++) {
			// Use chain-member constructor that doesn't make additional network calls
			DeepVioletX509Certificate dvCert = new DeepVioletX509Certificate(eng, chain[i], chain, i);
			list.add(dvCert);
		}
		dvChain = list.toArray(new DeepVioletX509Certificate[0]);
	}

	/**
	 * Assign trust state for a chain member based on its position.
	 */
	private void assignTrustStateForChainMember(int chainIndex) {
		// For chain members, we derive trust from whether their issuer is in the Java trust store
		if (bJavaRootCertificate) {
			iTrustState = TrustState.TRUSTED;
		} else if (bSelfSignedCertificate && chainIndex > 0) {
			// Self-signed intermediate or root that's not in Java trust store
			iTrustState = TrustState.UNTRUSTED;
		} else {
			// Intermediate certs inherit trust from chain validation
			iTrustState = TrustState.UNKNOWN;
		}
	}

	/**
	 * Run revocation checks for a chain member using the preloaded chain.
	 */
	private void assignRevocationStatusForChainMember(int chainIndex) {
		try {
			if (chain == null || chain.length == 0) {
				return;
			}

			// Find the issuer cert (next in chain, or self if last/self-signed)
			X509Certificate issuerCert;
			if (chainIndex + 1 < chain.length) {
				issuerCert = chain[chainIndex + 1];
			} else {
				// Last cert in chain or self-signed - use self as issuer
				issuerCert = cert;
			}

			revocationStatus = RevocationChecker.check(cert, issuerCert);
			RevocationChecker.checkOneCrl(cert, revocationStatus);

			// Check for SCTs in OCSP stapling response (only for end-entity)
			if (chainIndex == 0) {
				checkOcspStaplingScts();
			}
		} catch (Exception e) {
			logger.error("Revocation check failed for chain member " + subjectDN, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getSigningAlgorithm()
	 */
	public String getSigningAlgorithm() {
		return signingAlgorithm;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getCertificateSerialNumber()
	 */
	public BigInteger getCertificateSerialNumber() {
		return certificateSerialNumber;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getSigningAlgorithmOID()
	 */
	public String getSigningAlgorithmOID(){
		return signingAlgorithmOID;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getCertificateVersion()
	 */
	public int getCertificateVersion(){
		return iCertificateVersion;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getNotValidBefore()
	 */
	public String getNotValidBefore(){
		return notValidBefore;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getNotValidAfter()
	 */
	public String getNotValidAfter(){
		return notValidAfter;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getValidityState()
	 */
	public ValidState getValidityState(){
		return iValidityState;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getSubjectDN()
	 */
	public String getSubjectDN(){
		return subjectDN;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getIssuerDN()
	 */
	public String getIssuerDN(){
		return issuerDN;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getTrustState()
	 */
	public TrustState getTrustState(){
		return iTrustState;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.isSelfSignedCertificate()
	 */
	public boolean isSelfSignedCertificate(){
		return bSelfSignedCertificate;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.isJavaRootCertificate()
	 */
	public boolean isJavaRootCertificate(){
		return bJavaRootCertificate;
	}

	public String getPublicKeyAlgorithm() {
		return publicKeyAlgorithm;
	}

	public int getPublicKeySize() {
		return publicKeySize;
	}

	public String getPublicKeyCurve() {
		return publicKeyCurve;
	}

	public long getDaysUntilExpiration() {
		return daysUntilExpiration;
	}

	public IRevocationStatus getRevocationStatus() {
		return revocationStatus;
	}

	public List<String> getSubjectAlternativeNames() {
		return subjectAlternativeNames;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getCertificateFingerPrint()
	 */
	public String getCertificateFingerPrint(){
		return certificateFingerPrint;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getNonCritOIDProperties()
	 */
	public String[] getNonCritOIDProperties() {
		Set<String> oids = nonCritOidMap.keySet();
		return oids.toArray(new String[0]);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getNonCritPropertyValue(String)
	 */
	public String getNonCritPropertyValue(String key) {
		if( key==null || !nonCritOidMap.containsKey(key) ) return null;
		return nonCritOidMap.get(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getCritPropertyValue()
	 */
	public String[] getCritOIDProperties() {
		Set<String> oids = critOidMap.keySet();
		return oids.toArray(new String[0]);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getCritPropertyValue(String)
	 */
	public String getCritPropertyValue(String key) {
		if( key==null || !critOidMap.containsKey(key) ) return null;
		return critOidMap.get(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.isContainsNonCritPropertyKey()
	 */
	public boolean isContainsNonCritPropertyKey(String key) {
		return nonCritOidMap.containsKey(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.isContainsCritPropertyKey()
	 */
	public boolean isContainsCritPropertyKey(String key) {
		return critOidMap.containsKey(key);
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.getCertificateChain()
	 *
	 * Note: dvChain is now built eagerly during onlineInitializationOnly()
	 * so this method is a pure getter with no network calls.
	 */
	public synchronized IX509Certificate[] getCertificateChain() throws DeepVioletException {
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
	 * @throws DeepVioletException Thrown on problems
	 */
	private void assignCertificateChain() throws DeepVioletException {
			try {
				chain = CipherSuiteUtil.getServerCertificateChain(eng.getSession().getURL());
			} catch (SSLHandshakeException e ) {
				if( e.getMessage().indexOf("PKIX") > 0 ) {
					String msg = "Certificate chain failed validation. err=" + e.getMessage();
					logger.error(msg,e);
					throw new DeepVioletException(msg,e);
				}else{
					String msg = "SSLHandshakeException. err=" + e.getMessage();
					logger.error(msg,e);
					throw new DeepVioletException(msg,e);
				}
					
			} catch (Exception e) {
				String msg = "Problem fetching certificates. err=" + e.getMessage();
				logger.error(msg,e);
				throw new DeepVioletException(msg,e);
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
    private void assignTrustState() throws DeepVioletException {
		try {
			//todo should look at a different way to do this later
			boolean bTrusted = CipherSuiteUtil.checkTrustedCertificate( chain, eng.getSession().getURL() );
			if( bTrusted ) {
				iTrustState = TrustState.TRUSTED;
			} else {
				iTrustState = TrustState.UNTRUSTED;
			}
		} catch( KeyStoreException e ) {
			iTrustState = TrustState.UNKNOWN;
			throw new DeepVioletException("Problem accessing keystore, err=" + e.getMessage(),e);
		} catch( NoSuchAlgorithmException e ) {
			iTrustState = TrustState.UNKNOWN;
			throw new DeepVioletException("No cipher suite available, err=" + e.getMessage(),e);
		} catch( UnknownHostException e ) {
			iTrustState = TrustState.UNKNOWN;
			throw new DeepVioletException("Unknown host, err=" + e.getMessage(),e);
		} catch( IOException e ) {
			throw new DeepVioletException("File system problem, err=" + e.getMessage(),e);
		}
	}		

	/**
	 * Run revocation checks using the issuer cert from the chain.
	 */
	private void assignRevocationStatus() {
		try {
			if (chain != null && chain.length >= 2) {
				// chain[0] = end-entity, chain[1] = issuer
				X509Certificate issuerCert = chain.length > 1 ? chain[1] : chain[0];
				revocationStatus = RevocationChecker.check(cert, issuerCert);
				RevocationChecker.checkOneCrl(cert, revocationStatus);
				// Check for SCTs in OCSP stapling response
				checkOcspStaplingScts();
			} else if (chain != null && chain.length == 1) {
				// Self-signed: use self as issuer
				revocationStatus = RevocationChecker.check(cert, cert);
				RevocationChecker.checkOneCrl(cert, revocationStatus);
				// Check for SCTs in OCSP stapling response
				checkOcspStaplingScts();
			}
		} catch (Exception e) {
			logger.error("Revocation check failed for " + subjectDN, e);
		}
	}

	/**
	 * Check for SCTs in the OCSP stapling response from the session.
	 */
	private void checkOcspStaplingScts() {
		if (revocationStatus == null || eng == null) {
			return;
		}
		try {
			ISession session = eng.getSession();
			byte[] stapledResponse = session.getStapledOcspResponse();
			RevocationChecker.checkOcspStaplingScts(stapledResponse, revocationStatus);
		} catch (Exception e) {
			logger.debug("Could not check OCSP stapling SCTs", e);
		}
	}

	/**
	 * Look up the EC curve name from parameters.
	 */
	private static String lookupECCurveName(ECParameterSpec ecSpec) {
		return ECCurveNames.lookupCurveName(ecSpec);
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IX509Certificate.toString()
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
	 * @see com.mps.deepviolet.api.IX509Certificate.equals(Object)
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
			if( obj instanceof IX509Certificate ) {
				IX509Certificate c = (IX509Certificate)obj;

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
