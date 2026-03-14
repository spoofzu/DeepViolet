package com.mps.deepviolet.api;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.SSLHandshakeException;

import com.mps.deepviolet.api.ai.AiAnalysisException;
import com.mps.deepviolet.api.ai.AiConfig;
import com.mps.deepviolet.api.ai.AiAnalysisService;
import com.mps.deepviolet.api.tls.TlsMetadata;
import com.mps.deepviolet.api.tls.TlsSocket;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint;
import com.mps.deepviolet.api.scoring.RiskScorer;
import com.mps.deepviolet.api.scoring.rules.RuleContext;
import com.mps.deepviolet.api.scoring.rules.RulePolicy;
import com.mps.deepviolet.api.scoring.rules.RulePolicyLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Utility class to access DeepViolet SSL/TLS features from API
 * @author Milton Smith
 */
class DeepVioletEngine implements IEngine {
	
	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.DeepVioletEngine");
	
	//private HashMap<ENGINE_PROPERTIES,String> map = new HashMap<ENGINE_PROPERTIES,String>();
	private HashMap<String,String> map = new HashMap<String,String>();
	
	int iVersionMajor = -1; 
	int iVersionMinor = -1; 
	int iVersionBuild = -1; 
	boolean bSnapShot = false;
	
	private final String EOL = System.getProperty("line.separator");
	private final URL url;
	
	private MutableSession session;
	private ServerMetadata servmeta;
	private TlsMetadata tlsMetadata;
	private String tlsFingerprint;
	private IDnsStatus dnsStatus;
	private Boolean fallbackScsvSupported;
	
	/**
	 * Construct engine with default (no background task).
	 * @param session Initialized session
	 * @param cipher_name_convention Cipher suite name convention
	 * @throws DeepVioletException Thrown on problems
	 */
	DeepVioletEngine( ISession session,  ISession.CIPHER_NAME_CONVENTION cipher_name_convention ) throws DeepVioletException {
		this( session, cipher_name_convention, null );
	}

	/**
	 * Construct engine with optional background task for status updates.
	 * @param session Initialized session
	 * @param cipher_name_convention Cipher suite name convention
	 * @param dvtask Background task for status updates, or null
	 * @throws DeepVioletException Thrown on problems
	 */
	DeepVioletEngine( ISession session,  ISession.CIPHER_NAME_CONVENTION cipher_name_convention,  BackgroundTask dvtask  ) throws DeepVioletException {
		this(session, cipher_name_convention, dvtask, null);
	}

	/**
	 * Construct engine with optional background task and protocol filter.
	 * @param session Initialized session
	 * @param cipher_name_convention Cipher suite name convention
	 * @param dvtask Background task for status updates, or null
	 * @param enabledProtocols set of protocol version codes to probe, or null for all
	 * @throws DeepVioletException Thrown on problems
	 */
	DeepVioletEngine( ISession session,  ISession.CIPHER_NAME_CONVENTION cipher_name_convention,  BackgroundTask dvtask, java.util.Set<Integer> enabledProtocols  ) throws DeepVioletException {

		try {
			this.session = (MutableSession)session; //TODO: Ugly bug works
			this.url = session.getURL();

			// Update callers task with status or create a dummy task.
			dvtask = (dvtask == null) ? new BackgroundTask() : dvtask;

			servmeta = CipherSuiteUtil.getServerMetadataInstance(url, cipher_name_convention, this.session, dvtask, enabledProtocols);
			if( servmeta == null ) {
				String msg = "Unable to create DeepVioletEngine.  ServerMetadata is null";
				logger.error(msg);
				throw new DeepVioletException(msg);
			}
			
			Properties p = new Properties();
			try (InputStream is = this.getClass().getClassLoader().getResourceAsStream("dvmaven.properties")) {
				p.load(is);
			}
			String sVersion = p.getProperty("dvversion");
			logger.debug("DV Maven version string, dvversion="+sVersion);
			
			if( sVersion != null && sVersion.length() > 0 ) {
			
				// Build the DV version information
				int f1 = sVersion.indexOf('.');
				int f2 = sVersion.lastIndexOf('.');
				// Corrections to f3 by Jean-Julien Alvado, thank you!
				int f3 = sVersion.lastIndexOf('-');
				if (f3 == -1 ) {
					f3 = sVersion.length();
				} else {
					bSnapShot = true;
				}

				if( f1 > 0 && f2 > 0 ) {
			
					try {
						iVersionMajor = Integer.parseInt(sVersion.substring(0,f1));
						iVersionMinor = Integer.parseInt(sVersion.substring(f1+1,f2));
						iVersionBuild = Integer.parseInt(sVersion.substring(f2+1,f3));
					}catch(Exception e) {
						iVersionMajor = -1;
						iVersionMinor = -1;
						iVersionBuild = -1;
						String msg = "Problem with 'dvversion' Maven property value.  dvversion="+sVersion+", f1="+f1+", f2="+f2+", f3="+f3;
						logger.debug(msg);
						throw new DeepVioletException(msg);
					}
				
				} else {
					logger.debug("Problem with 'dvversion' Maven property value.  dvversion="+sVersion+", f1="+f1+", f2="+f2+", f3="+f3);
				}
				
			}
			
		} catch( DeepVioletException e ) {
			throw e;
		} catch( Exception e ) {
			String msg = "Problem creating DeepVioletEngine. err="+e.getMessage();	
			logger.error(msg,e );
			throw new DeepVioletException(msg,e );
		}
		
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getSession()
	 */
	public ISession getSession() {
		return session;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getDeepVioletMajorVersion()
	 */
	public final int getDeepVioletMajorVersion() {
		return iVersionMajor;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getDeepVioletMinorVersion()
	 */
	public final int getDeepVioletMinorVersion() {
		return iVersionMinor;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getDeepVioletBuildVersion()
	 */
	public final int getDeepVioletBuildVersion() {
		return iVersionBuild;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getDeepVioletStringVersion()
	 */
	public final String getDeepVioletStringVersion() {
		StringBuilder buff = new StringBuilder();
		buff.append(iVersionMajor);
		buff.append('.');
		buff.append(iVersionMinor);
		buff.append('.');
		buff.append(iVersionBuild);
		String sSnapShot = (bSnapShot) ? "-SNAPSHOT" : "";
		buff.append(sSnapShot);
		return buff.toString();
	}
 
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getCipherSuites()
	 */
	public final ICipherSuite[] getCipherSuites() throws DeepVioletException {
		List<ICipherSuite> list = new ArrayList<ICipherSuite>();
		URL url = session.getURL();
		try {
			Map<String,List<String>> allCiphers = new HashMap<String, List<String>>();
		
			if( servmeta == null ) {
				return null;
			}

			// TODO: Move protocol versions to own type
			if( servmeta.containsKey("getServerMetadataInstance","SSLv2") ) allCiphers.put("SSLv2",servmeta.getVectorValue("getServerMetadataInstance","SSLv2"));
			if( servmeta.containsKey("getServerMetadataInstance","SSLv3") ) allCiphers.put("SSLv3",servmeta.getVectorValue("getServerMetadataInstance","SSLv3"));
			if( servmeta.containsKey("getServerMetadataInstance","TLSv1.0") ) allCiphers.put("TLSv1.0",servmeta.getVectorValue("getServerMetadataInstance","TLSv1.0"));
			if( servmeta.containsKey("getServerMetadataInstance","TLSv1.1") ) allCiphers.put("TLSv1.1",servmeta.getVectorValue("getServerMetadataInstance","TLSv1.1"));
			if( servmeta.containsKey("getServerMetadataInstance","TLSv1.2") ) allCiphers.put("TLSv1.2",servmeta.getVectorValue("getServerMetadataInstance","TLSv1.2"));
			if( servmeta.containsKey("getServerMetadataInstance","TLSv1.3") ) allCiphers.put("TLSv1.3",servmeta.getVectorValue("getServerMetadataInstance","TLSv1.3"));

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
					MutableCipherSuite suite = new MutableCipherSuite(cipher,strength,tlsVersion);
					list.add(suite);
				}
			}
		} catch( Exception e ) {
			String msg = "Problem fetching ciphersuites. err="+e.getMessage();	
			logger.error(msg,e );
			throw new DeepVioletException(msg,e );
		}
		return (ICipherSuite[])list.toArray(new MutableCipherSuite[0]);	
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getCertificate()
	 */
	public final IX509Certificate getCertificate() throws DeepVioletException {
		X509Certificate cert;
		IX509Certificate dvCert;
		try {
			cert = CipherSuiteUtil.getServerCertificate(session.getURL());					
			dvCert = new DeepVioletX509Certificate(this,cert);
		} catch (Exception e) {
			String msg = "Problem fetching certificate. err="+e.getMessage();	
			logger.error(msg,e );
			throw new DeepVioletException(msg,e );
		}
		return dvCert;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#writeCertificate(java.lang.String)
	 */
	public final long writeCertificate( String file ) throws DeepVioletException {
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
					DeepVioletException e = new DeepVioletException("Write certificate failed. reason=directory WRITE required.  dir="+path );
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
				 StringBuilder pemBuff = new StringBuilder(pemB64.length());
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
				DeepVioletException e1 = new DeepVioletException("Error writing file.  file="+f.getAbsolutePath(), e);
				throw e1;
			} finally {
				try { out.close(); } catch(IOException e1) {}	
			}
		} catch (SSLHandshakeException e ) {
			if( e.getMessage().indexOf("PKIX") > 0 ) {
				DeepVioletException e1 = new DeepVioletException("Certificate chain failed validation. err="+e.getMessage(),e );
				throw e1;
			} else {
				DeepVioletException e1 = new DeepVioletException("SSLHandshakeException. err="+e.getMessage(),e );
				throw e1;
			}  	
		} catch (Exception e) {
			DeepVioletException e1 = new DeepVioletException("SSLHandshakeException. err="+e.getMessage(),e);
			throw e1;
		}
		
		long sz = (derenccert!=null) ? derenccert.length : 0;
		return sz;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#isDeepVioletSnapShot()
	 */
	public boolean isDeepVioletSnapShot() {
		return bSnapShot;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getTlsFingerprint()
	 */
	public String getTlsFingerprint() throws DeepVioletException {
		if (tlsFingerprint == null) {
			try {
				int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
				tlsFingerprint = TlsServerFingerprint.compute(url.getHost(), port);
			} catch (Exception e) {
				String msg = "Problem computing TLS fingerprint. err=" + e.getMessage();
				logger.error(msg, e);
				throw new DeepVioletException(msg, e);
			}
		}
		return tlsFingerprint;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getSCTs()
	 */
	public List<byte[]> getSCTs() throws DeepVioletException {
		try {
			// Ensure we have TLS metadata
			if (tlsMetadata == null) {
				fetchTlsMetadata();
			}
			if (tlsMetadata != null) {
				return tlsMetadata.getAllSCTs();
			}
			return new ArrayList<>();
		} catch (Exception e) {
			String msg = "Problem extracting SCTs. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getTlsMetadata()
	 */
	public TlsMetadata getTlsMetadata() throws DeepVioletException {
		try {
			if (tlsMetadata == null) {
				fetchTlsMetadata();
			}
			return tlsMetadata;
		} catch (Exception e) {
			String msg = "Problem getting TLS metadata. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/**
	 * Fetch TLS metadata using TlsSocket (raw TLS parsing).
	 */
	private void fetchTlsMetadata() {
		try {
			int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
			tlsMetadata = TlsSocket.connect(url.getHost(), port);
		} catch (Exception e) {
			logger.warn("Failed to fetch TLS metadata: " + e.getMessage());
			// Don't throw - tlsMetadata will remain null
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getFallbackScsvSupported()
	 */
	public Boolean getFallbackScsvSupported() throws DeepVioletException {
		if (fallbackScsvSupported == null) {
			try {
				int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
				fallbackScsvSupported = TlsSocket.testFallbackScsv(url.getHost(), port);
			} catch (Exception e) {
				logger.warn("Fallback SCSV test failed: " + e.getMessage());
				return null;
			}
		}
		return fallbackScsvSupported;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getDnsStatus()
	 */
	public IDnsStatus getDnsStatus() throws DeepVioletException {
		if (dnsStatus == null) {
			try {
				int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
				dnsStatus = DnsSecurityChecker.check(url.getHost(), port);
			} catch (Exception e) {
				logger.warn("DNS security check failed: " + e.getMessage());
				dnsStatus = DnsStatus.unavailable();
			}
		}
		return dnsStatus;
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#buildRuleContext()
	 */
	public RuleContext buildRuleContext() throws DeepVioletException {
		try {
			return RuleContext.from(this);
		} catch (Exception e) {
			String msg = "Problem building rule context. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getRiskScore(RuleContext)
	 */
	public IRiskScore getRiskScore(RuleContext context) throws DeepVioletException {
		try {
			RulePolicy rulePolicy = RulePolicyLoader.tryLoad();
			if (rulePolicy == null) {
				throw new IllegalStateException("No YAML rules found on classpath or via system property dv.scoring.rules");
			}
			String hostUrl = session.getURL().toString();
			return RiskScorer.computeScore(context, hostUrl, rulePolicy);
		} catch (Exception e) {
			String msg = "Problem computing risk score from context. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getRiskScore(RuleContext, InputStream)
	 */
	public IRiskScore getRiskScore(RuleContext context, InputStream userRulesStream) throws DeepVioletException {
		try {
			RulePolicy systemPolicy = RulePolicyLoader.tryLoad();
			if (systemPolicy == null) {
				throw new IllegalStateException("No YAML rules found on classpath or via system property dv.scoring.rules");
			}
			RulePolicy userPolicy = RulePolicyLoader.loadUserRules(userRulesStream);
			RulePolicy mergedPolicy = systemPolicy.mergeUserRules(userPolicy);
			String hostUrl = session.getURL().toString();
			return RiskScorer.computeScore(context, hostUrl, mergedPolicy);
		} catch (Exception e) {
			String msg = "Problem computing risk score with user rules from context. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getRiskScore()
	 */
	public IRiskScore getRiskScore() throws DeepVioletException {
		try {
			RulePolicy rulePolicy = RulePolicyLoader.tryLoad();
			if (rulePolicy == null) {
				throw new IllegalStateException("No YAML rules found on classpath or via system property dv.scoring.rules");
			}
			RiskScorer scorer = new RiskScorer(this, rulePolicy);
			return scorer.computeScore();
		} catch (Exception e) {
			String msg = "Problem computing risk score. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getRiskScore(String)
	 */
	public IRiskScore getRiskScore(String rulesPath) throws DeepVioletException {
		try {
			RulePolicy rulePolicy = RulePolicyLoader.loadFromFile(rulesPath);
			RiskScorer scorer = new RiskScorer(this, rulePolicy);
			return scorer.computeScore();
		} catch (Exception e) {
			String msg = "Problem computing risk score. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getRiskScore(InputStream)
	 */
	public IRiskScore getRiskScore(InputStream userRulesStream) throws DeepVioletException {
		try {
			RulePolicy systemPolicy = RulePolicyLoader.tryLoad();
			if (systemPolicy == null) {
				throw new IllegalStateException("No YAML rules found on classpath or via system property dv.scoring.rules");
			}
			RulePolicy userPolicy = RulePolicyLoader.loadUserRules(userRulesStream);
			RulePolicy mergedPolicy = systemPolicy.mergeUserRules(userPolicy);
			RiskScorer scorer = new RiskScorer(this, mergedPolicy);
			return scorer.computeScore();
		} catch (Exception e) {
			String msg = "Problem computing risk score with user rules. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getAiAnalysis(AiConfig)
	 */
	public String getAiAnalysis(AiConfig config) throws DeepVioletException {
		try {
			String report = buildPlainTextReport();
			InputStream reportStream = new ByteArrayInputStream(
					report.getBytes(StandardCharsets.UTF_8));
			return getAiAnalysis(reportStream, config);
		} catch (DeepVioletException e) {
			throw e;
		} catch (Exception e) {
			String msg = "Problem building AI analysis report. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.api.IEngine#getAiAnalysis(InputStream, AiConfig)
	 */
	public String getAiAnalysis(InputStream scanReport, AiConfig config) throws DeepVioletException {
		try {
			AiAnalysisService aiService = new AiAnalysisService();
			return aiService.analyze(scanReport, config);
		} catch (AiAnalysisException e) {
			throw new DeepVioletException("AI analysis failed: " + e.getMessage(), e);
		} catch (Exception e) {
			String msg = "Problem performing AI analysis. err=" + e.getMessage();
			logger.error(msg, e);
			throw new DeepVioletException(msg, e);
		}
	}

	/**
	 * Build a plain text summary from the current engine state for AI analysis.
	 */
	private String buildPlainTextReport() throws DeepVioletException {
		StringBuilder sb = new StringBuilder();

		// Session info
		sb.append("[Session Information]\n");
		sb.append("URL=").append(url.toString()).append("\n");
		try {
			String protocol = session.getSessionPropertyValue(
					ISession.SESSION_PROPERTIES.NEGOTIATED_PROTOCOL);
			String cipher = session.getSessionPropertyValue(
					ISession.SESSION_PROPERTIES.NEGOTIATED_CIPHER_SUITE);
			if (protocol != null) sb.append("Negotiated Protocol=").append(protocol).append("\n");
			if (cipher != null) sb.append("Negotiated Cipher Suite=").append(cipher).append("\n");
		} catch (Exception e) {
			logger.debug("Could not get session properties for AI report", e);
		}
		sb.append("\n");

		// Risk score
		try {
			IRiskScore score = getRiskScore();
			if (score != null) {
				sb.append("[TLS Risk Assessment]\n");
				sb.append("Overall Score=").append(score.getTotalScore()).append("/100\n");
				sb.append("Letter Grade=").append(score.getLetterGrade()).append("\n");
				sb.append("Risk Level=").append(score.getRiskLevel()).append("\n");
				for (IRiskScore.ICategoryScore cat : score.getCategoryScores()) {
					sb.append("\n").append(cat.getDisplayName()).append(":\n");
					sb.append("   Score=").append(String.format("%.1f", cat.getScore())).append("\n");
					sb.append("   Risk Level=").append(cat.getRiskLevel()).append("\n");
					if (cat.getSummary() != null && !cat.getSummary().isEmpty()) {
						sb.append("   Summary=").append(cat.getSummary()).append("\n");
					}
					for (IRiskScore.IDeduction d : cat.getDeductions()) {
						sb.append("   ").append(d.getRuleId())
								.append(" [").append(d.getSeverity()).append("] ")
								.append(d.getDescription())
								.append(" (").append(String.format("%.0f", d.getScore())).append(" pts)\n");
					}
				}
				sb.append("\n");
			}
		} catch (Exception e) {
			logger.debug("Could not compute risk score for AI report", e);
		}

		// Cipher suites
		try {
			ICipherSuite[] ciphers = getCipherSuites();
			if (ciphers != null && ciphers.length > 0) {
				sb.append("[Cipher Suites]\n");
				for (ICipherSuite cs : ciphers) {
					sb.append(cs.getSuiteName()).append(" [")
							.append(cs.getStrengthEvaluation()).append("] ")
							.append(cs.getHandshakeProtocol()).append("\n");
				}
				sb.append("\n");
			}
		} catch (Exception e) {
			logger.debug("Could not get cipher suites for AI report", e);
		}

		// Certificate info
		try {
			IX509Certificate cert = getCertificate();
			if (cert != null) {
				sb.append("[Certificate]\n");
				sb.append("Subject=").append(cert.getSubjectDN()).append("\n");
				sb.append("Issuer=").append(cert.getIssuerDN()).append("\n");
				sb.append("Valid From=").append(cert.getNotValidBefore()).append("\n");
				sb.append("Valid Until=").append(cert.getNotValidAfter()).append("\n");
				sb.append("Validity=").append(cert.getValidityState()).append("\n");
				sb.append("Days Until Expiration=").append(cert.getDaysUntilExpiration()).append("\n");
				sb.append("Trust State=").append(cert.getTrustState()).append("\n");
				sb.append("Self-Signed=").append(cert.isSelfSignedCertificate()).append("\n");
				sb.append("Signing Algorithm=").append(cert.getSigningAlgorithm()).append("\n");
				sb.append("Public Key Algorithm=").append(cert.getPublicKeyAlgorithm()).append("\n");
				sb.append("Public Key Size=").append(cert.getPublicKeySize()).append("\n");
				String curve = cert.getPublicKeyCurve();
				if (curve != null) sb.append("Public Key Curve=").append(curve).append("\n");
				sb.append("\n");
			}
		} catch (Exception e) {
			logger.debug("Could not get certificate for AI report", e);
		}

		// DNS status
		try {
			IDnsStatus dns = getDnsStatus();
			if (dns != null) {
				sb.append("[DNS Security]\n");
				sb.append("CAA Records Present=").append(dns.hasCaaRecords()).append("\n");
				sb.append("DANE/TLSA Records Present=").append(dns.hasTlsaRecords()).append("\n");
				sb.append("\n");
			}
		} catch (Exception e) {
			logger.debug("Could not get DNS status for AI report", e);
		}

		// TLS fingerprint
		try {
			String fingerprint = getTlsFingerprint();
			if (fingerprint != null) {
				sb.append("[TLS Fingerprint]\n");
				sb.append("Fingerprint=").append(fingerprint).append("\n");
				sb.append("\n");
			}
		} catch (Exception e) {
			logger.debug("Could not get TLS fingerprint for AI report", e);
		}

		return sb.toString();
	}

//	public String getPropertyValue( String keyname ) throws DeepVioletException {
//		URL url = session.getURL();
//		try {
//			Map<String,List<String>> allCiphers = new HashMap<String, List<String>>();
//			if( servmeta == null ) {
//				return null;
//			}
//			
//			List<String> keys = servmeta.getKeys("analysis");
//			for( String key: keys ) {
//				map.put(key, servmeta.getScalarValue("analysis", key));
//			}
//			
//		} catch( Exception e ) {
//			String msg = "Problem fetching ciphersuites. err="+e.getMessage();	
//			logger.error(msg,e );
//			throw new DeepVioletException(msg,e);
//		}
//		
//		return map.get(keyname);
//	}
//	
//	public String[] getPropertyNames() {
//		return map.keySet().toArray(new String[0]);
//	}
//	
//	void setProperty( String name, String value ) {
//		map.put(name,value);
//	}
	
	
}

