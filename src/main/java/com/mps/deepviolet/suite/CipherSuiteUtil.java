package com.mps.deepviolet.suite;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import sun.security.provider.certpath.OCSP;
//import sun.security.provider.certpath.OCSP.RevocationStatus;

public class CipherSuiteUtil {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.suite.CipherSuiteUtil");
	
	// Common OIDs to Extention Mappings
	private static final HashMap<String,String> OIDMAP = new HashMap<String,String>();
	
	
	// FYI TLS 1.2   http://tools.ietf.org/html/rfc5246
	
	/** Millisec delay to server to play nice. */
	private static final int NICE = 1300;
	

	private static final String SSLV3 = "SSLv3";
	private static final String TLS1_0 = "TLS1.0";
	private static final String TLS1_1 = "TLS1.1";
	private static final String TLS1_2 = "TLS1.2";
	private static final String SUNCAT = "Uncategorized";
	
	// SSLv2 cipher suites.
	private static final String RC4_128_WITH_MD5 = "RC4_128_WITH_MD5";
	private static final String RC4_128_EXPORT40_WITH_MD5 = "RC4_128_EXPORT40_WITH_MD5";
	private static final String RC2_128_CBC_WITH_MD5 = "RC2_128_CBC_WITH_MD5";
	private static final String RC2_128_CBC_EXPORT40_WITH_MD5 = "RC2_128_CBC_EXPORT40_WITH_MD5";
	private static final String IDEA_128_CBC_WITH_MD5 = "IDEA_128_CBC_WITH_MD5";
	private static final String DES_64_CBC_WITH_MD5 = "DES_64_CBC_WITH_MD5";
	private static final String DES_192_EDE3_CBC_WITH_MD5 = "DES_192_EDE3_CBC_WITH_MD5";
	
	// SSLv3 cipher suites and TLS1.0 cipher suites.
	private static final String RSA_WITH_NULL_MD5 = "RSA_WITH_NULL_MD5";
	//private static final String RC4_128_WITH_MD5 = "RC4_128_WITH_MD5";
	private static final String RSA_WITH_NULL_SHA = "RSA_WITH_NULL_SHA";
	private static final String RSA_EXPORT_WITH_RC4_40_MD5 = "RSA_EXPORT_WITH_RC4_40_MD5";
	private static final String RSA_WITH_RC4_128_MD5 = "RSA_WITH_RC4_128_MD5";
	private static final String RSA_WITH_RC4_128_SHA = "RSA_WITH_RC4_128_SHA";
	private static final String RSA_EXPORT_WITH_RC2_CBC_40_MD5 = "RSA_EXPORT_WITH_RC2_CBC_40_MD5";
	private static final String RSA_WITH_IDEA_CBC_SHA = "RSA_WITH_IDEA_CBC_SHA";
	private static final String RSA_EXPORT_WITH_DES40_CBC_SHA = "RSA_EXPORT_WITH_DES40_CBC_SHA";
	private static final String RSA_WITH_DES_CBC_SHA = "RSA_WITH_DES_CBC_SHA";
	private static final String RSA_WITH_3DES_EDE_CBC_SHA = "RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String DH_DSS_EXPORT_WITH_DES40_CBC_SHA = "DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
	private static final String DH_DSS_WITH_DES_CBC_SHA = "DH_DSS_WITH_DES_CBC_SHA";
	private static final String DH_DSS_WITH_3DES_EDE_CBC_SHA = "DH_DSS_WITH_3DES_EDE_CBC_SHA";
	private static final String DH_RSA_EXPORT_WITH_DES40_CBC_SHA = "DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
	private static final String DH_RSA_WITH_DES_CBC_SHA = "DH_RSA_WITH_DES_CBC_SHA";
	private static final String DH_RSA_WITH_3DES_EDE_CBC_SHA = "DH_RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = "DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
	private static final String DHE_DSS_WITH_DES_CBC_SHA = "DHE_DSS_WITH_DES_CBC_SHA";
	private static final String DHE_DSS_WITH_3DES_EDE_CBC_SHA = "DHE_DSS_WITH_3DES_EDE_CBC_SHA";
	private static final String DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = "DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
	private static final String DHE_RSA_WITH_DES_CBC_SHA = "DHE_RSA_WITH_DES_CBC_SHA";
	private static final String DHE_RSA_WITH_3DES_EDE_CBC_SHA = "DHE_RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String DH_anon_EXPORT_WITH_RC4_40_MD5 = "DH_anon_EXPORT_WITH_RC4_40_MD5";
	private static final String DH_anon_WITH_RC4_128_MD5 = "DH_anon_WITH_RC4_128_MD5";
	private static final String DH_anon_EXPORT_WITH_DES40_CBC_SHA = "DH_anon_EXPORT_WITH_DES40_CBC_SHA";
	private static final String DH_anon_WITH_DES_CBC_SHA = "DH_anon_WITH_DES_CBC_SHA";
	private static final String DH_anon_WITH_3DES_EDE_CBC_SHA = "DH_anon_WITH_3DES_EDE_CBC_SHA";
	
	// TLS1.1 cipher suites
	private static final String RSA_WITH_AES_128_CBC_SHA = "RSA_WITH_AES_128_CBC_SHA";
	private static final String DH_DSS_WITH_AES_128_CBC_SHA = "DH_DSS_WITH_AES_128_CBC_SHA";
	private static final String DH_RSA_WITH_AES_128_CBC_SHA = "DH_RSA_WITH_AES_128_CBC_SHA";
	private static final String DHE_DSS_WITH_AES_128_CBC_SHA = "DHE_DSS_WITH_AES_128_CBC_SHA";
	private static final String DHE_RSA_WITH_AES_128_CBC_SHA = "DHE_RSA_WITH_AES_128_CBC_SHA";
	private static final String DH_anon_WITH_AES_128_CBC_SHA = "DH_anon_WITH_AES_128_CBC_SHA";
	private static final String RSA_WITH_AES_256_CBC_SHA = "RSA_WITH_AES_256_CBC_SHA";
	private static final String DH_DSS_WITH_AES_256_CBC_SHA = "DH_DSS_WITH_AES_256_CBC_SHA";
	private static final String DH_RSA_WITH_AES_256_CBC_SHA = "DH_RSA_WITH_AES_256_CBC_SHA";
	private static final String DHE_DSS_WITH_AES_256_CBC_SHA = "DHE_DSS_WITH_AES_256_CBC_SHA";
	private static final String DHE_RSA_WITH_AES_256_CBC_SHA = "DHE_RSA_WITH_AES_256_CBC_SHA";
	private static final String DH_anon_WITH_AES_256_CBC_SHA = "DH_anon_WITH_AES_256_CBC_SHA";
	
	// TLS1.2 cipher suites
	private static final String RSA_WITH_NULL_SHA256 = "RSA_WITH_NULL_SHA256";
	private static final String RSA_WITH_AES_128_CBC_SHA256 = "RSA_WITH_AES_128_CBC_SHA256";
	private static final String RSA_WITH_AES_256_CBC_SHA256 = "RSA_WITH_AES_256_CBC_SHA256";
	private static final String DH_DSS_WITH_AES_128_CBC_SHA256 = "DH_DSS_WITH_AES_128_CBC_SHA256";
	private static final String DH_RSA_WITH_AES_128_CBC_SHA256 = "DH_RSA_WITH_AES_128_CBC_SHA256";
	private static final String DHE_DSS_WITH_AES_128_CBC_SHA256 = "DHE_DSS_WITH_AES_128_CBC_SHA256";
	private static final String DHE_RSA_WITH_AES_128_CBC_SHA256 = "DHE_RSA_WITH_AES_128_CBC_SHA256";
	private static final String DH_DSS_WITH_AES_256_CBC_SHA256 = "DH_DSS_WITH_AES_256_CBC_SHA256";
	private static final String DH_RSA_WITH_AES_256_CBC_SHA256 = "DH_RSA_WITH_AES_256_CBC_SHA256";
	private static final String DHE_DSS_WITH_AES_256_CBC_SHA256 = "DHE_DSS_WITH_AES_256_CBC_SHA256";
	private static final String DHE_RSA_WITH_AES_256_CBC_SHA256 = "DHE_RSA_WITH_AES_256_CBC_SHA256";
	private static final String DH_anon_WITH_AES_128_CBC_SHA256 = "DH_anon_WITH_AES_128_CBC_SHA256";
	private static final String DH_anon_WITH_AES_256_CBC_SHA256 = "DH_anon_WITH_AES_256_CBC_SHA256";
	
	//UNCAT cipher suites
	private static final String TLS_PSK_WITH_RC4_128_SHA = "TLS_PSK_WITH_RC4_128_SHA";
	private static final String TLS_PSK_WITH_3DES_EDE_CBC_SHA = "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_PSK_WITH_AES_128_CBC_SHA = "TLS_PSK_WITH_AES_128_CBC_SHA";
	private static final String TLS_PSK_WITH_AES_256_CBC_SHA = "TLS_PSK_WITH_AES_256_CBC_SHA";
	private static final String TLS_DHE_PSK_WITH_RC4_128_SHA = "TLS_DHE_PSK_WITH_RC4_128_SHA";
	private static final String TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_DHE_PSK_WITH_AES_128_CBC_SHA = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
	private static final String TLS_DHE_PSK_WITH_AES_256_CBC_SHA = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
	private static final String TLS_RSA_PSK_WITH_RC4_128_SHA = "TLS_RSA_PSK_WITH_RC4_128_SHA";
	private static final String TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_RSA_PSK_WITH_AES_128_CBC_SHA = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
	private static final String TLS_RSA_PSK_WITH_AES_256_CBC_SHA = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
	private static final String TLS_RSA_WITH_SEED_CBC_SHA = "TLS_RSA_WITH_SEED_CBC_SHA";
	private static final String TLS_DH_DSS_WITH_SEED_CBC_SHA = "TLS_DH_DSS_WITH_SEED_CBC_SHA";
	private static final String TLS_DH_RSA_WITH_SEED_CBC_SHA = "TLS_DH_RSA_WITH_SEED_CBC_SHA";
	private static final String TLS_DHE_DSS_WITH_SEED_CBC_SHA = "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
	private static final String TLS_DHE_RSA_WITH_SEED_CBC_SHA = "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
	private static final String TLS_DH_anon_WITH_SEED_CBC_SHA = "TLS_DH_anon_WITH_SEED_CBC_SHA";
	private static final String TLS_RSA_WITH_AES_128_GCM_SHA256 = "TLS_RSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_RSA_WITH_AES_256_GCM_SHA384 = "TLS_RSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
	private static final String TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
	private static final String TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
	private static final String TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
	private static final String TLS_DH_anon_WITH_AES_128_GCM_SHA256 = "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
	private static final String TLS_DH_anon_WITH_AES_256_GCM_SHA384 = "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
	private static final String TLS_PSK_WITH_AES_128_GCM_SHA256 = "TLS_PSK_WITH_AES_128_GCM_SHA256";
	private static final String TLS_PSK_WITH_AES_256_GCM_SHA384 = "TLS_PSK_WITH_AES_256_GCM_SHA384";
	private static final String TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
	private static final String TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
	private static final String TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
	private static final String TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
	private static final String TLS_PSK_WITH_AES_128_CBC_SHA256 = "TLS_PSK_WITH_AES_128_CBC_SHA256";
	private static final String TLS_PSK_WITH_AES_256_CBC_SHA384 = "TLS_PSK_WITH_AES_256_CBC_SHA384";
	private static final String TLS_PSK_WITH_NULL_SHA256 = "TLS_PSK_WITH_NULL_SHA256";
	private static final String TLS_PSK_WITH_NULL_SHA384 = "TLS_PSK_WITH_NULL_SHA384";
	private static final String TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
	private static final String TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
	private static final String TLS_DHE_PSK_WITH_NULL_SHA256 = "TLS_DHE_PSK_WITH_NULL_SHA256";
	private static final String TLS_DHE_PSK_WITH_NULL_SHA384 = "TLS_DHE_PSK_WITH_NULL_SHA384";
	private static final String TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
	private static final String TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
	private static final String TLS_RSA_PSK_WITH_NULL_SHA256 = "TLS_RSA_PSK_WITH_NULL_SHA256";
	private static final String TLS_RSA_PSK_WITH_NULL_SHA384 = "TLS_RSA_PSK_WITH_NULL_SHA384";
	private static final String TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
	private static final String TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256";
	private static final String TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256";
	private static final String TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256";
	private static final String TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
	private static final String TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256";
	private static final String TLS_EMPTY_RENEGOTIATION_INFO_SCSV = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
	private static final String TLS_ECDH_ECDSA_WITH_NULL_SHA = "TLS_ECDH_ECDSA_WITH_NULL_SHA";
	private static final String TLS_ECDH_ECDSA_WITH_RC4_128_SHA = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
	private static final String TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
	private static final String TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
	private static final String TLS_ECDHE_ECDSA_WITH_NULL_SHA = "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
	private static final String TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
	private static final String TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
	private static final String TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
	private static final String TLS_ECDH_RSA_WITH_NULL_SHA = "TLS_ECDH_RSA_WITH_NULL_SHA";
	private static final String TLS_ECDH_RSA_WITH_RC4_128_SHA = "TLS_ECDH_RSA_WITH_RC4_128_SHA";
	private static final String TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
	private static final String TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
	private static final String TLS_ECDHE_RSA_WITH_NULL_SHA = "TLS_ECDHE_RSA_WITH_NULL_SHA";
	private static final String TLS_ECDHE_RSA_WITH_RC4_128_SHA = "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
	private static final String TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
	private static final String TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
	private static final String TLS_ECDH_anon_WITH_NULL_SHA = "TLS_ECDH_anon_WITH_NULL_SHA";
	private static final String TLS_ECDH_anon_WITH_RC4_128_SHA = "TLS_ECDH_anon_WITH_RC4_128_SHA";
	private static final String TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_ECDH_anon_WITH_AES_128_CBC_SHA = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
	private static final String TLS_ECDH_anon_WITH_AES_256_CBC_SHA = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
	private static final String TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_SRP_SHA_WITH_AES_128_CBC_SHA = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
	private static final String TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
	private static final String TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
	private static final String TLS_SRP_SHA_WITH_AES_256_CBC_SHA = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
	private static final String TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
	private static final String TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
	private static final String TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
	private static final String TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
	private static final String TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
	private static final String TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
	private static final String TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
	private static final String TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
	private static final String TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
	private static final String TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
	private static final String TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
	private static final String TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
	private static final String TLS_ECDHE_PSK_WITH_RC4_128_SHA = "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
	private static final String TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
	private static final String TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
	private static final String TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
	private static final String TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
	private static final String TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
	private static final String TLS_ECDHE_PSK_WITH_NULL_SHA = "TLS_ECDHE_PSK_WITH_NULL_SHA";
	private static final String TLS_ECDHE_PSK_WITH_NULL_SHA256 = "TLS_ECDHE_PSK_WITH_NULL_SHA256";
	private static final String TLS_ECDHE_PSK_WITH_NULL_SHA384 = "TLS_ECDHE_PSK_WITH_NULL_SHA384";
	private static final String TLS_RSA_WITH_ARIA_128_CBC_SHA256 = "TLS_RSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_RSA_WITH_ARIA_256_CBC_SHA384 = "TLS_RSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_RSA_WITH_ARIA_128_GCM_SHA256 = "TLS_RSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_RSA_WITH_ARIA_256_GCM_SHA384 = "TLS_RSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_PSK_WITH_ARIA_128_CBC_SHA256 = "TLS_PSK_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_PSK_WITH_ARIA_256_CBC_SHA384 = "TLS_PSK_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_PSK_WITH_ARIA_128_GCM_SHA256 = "TLS_PSK_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_PSK_WITH_ARIA_256_GCM_SHA384 = "TLS_PSK_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256";
	private static final String TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384";
	private static final String TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256";
	private static final String TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384";
	private static final String TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256";
	private static final String TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384";
	private static final String TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
	private static final String TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
	private static final String TLS_RSA_WITH_AES_128_CCM = "TLS_RSA_WITH_AES_128_CCM";
	private static final String TLS_RSA_WITH_AES_256_CCM = "TLS_RSA_WITH_AES_256_CCM";
	private static final String TLS_DHE_RSA_WITH_AES_128_CCM = "TLS_DHE_RSA_WITH_AES_128_CCM";
	private static final String TLS_DHE_RSA_WITH_AES_256_CCM = "TLS_DHE_RSA_WITH_AES_256_CCM";
	private static final String TLS_RSA_WITH_AES_128_CCM_8 = "TLS_RSA_WITH_AES_128_CCM_8";
	private static final String TLS_RSA_WITH_AES_256_CCM_8 = "TLS_RSA_WITH_AES_256_CCM_8";
	private static final String TLS_DHE_RSA_WITH_AES_128_CCM_8 = "TLS_DHE_RSA_WITH_AES_128_CCM_8";
	private static final String TLS_DHE_RSA_WITH_AES_256_CCM_8 = "TLS_DHE_RSA_WITH_AES_256_CCM_8";
	private static final String TLS_PSK_WITH_AES_128_CCM = "TLS_PSK_WITH_AES_128_CCM";
	private static final String TLS_PSK_WITH_AES_256_CCM = "TLS_PSK_WITH_AES_256_CCM";
	private static final String TLS_DHE_PSK_WITH_AES_128_CCM = "TLS_DHE_PSK_WITH_AES_128_CCM";
	private static final String TLS_DHE_PSK_WITH_AES_256_CCM = "TLS_DHE_PSK_WITH_AES_256_CCM";
	private static final String TLS_PSK_WITH_AES_128_CCM_8 = "TLS_PSK_WITH_AES_128_CCM_8";
	private static final String TLS_PSK_WITH_AES_256_CCM_8 = "TLS_PSK_WITH_AES_256_CCM_8";
	private static final String TLS_PSK_DHE_WITH_AES_128_CCM_8 = "TLS_PSK_DHE_WITH_AES_128_CCM_8";
	private static final String TLS_PSK_DHE_WITH_AES_256_CCM_8 = "TLS_PSK_DHE_WITH_AES_256_CCM_8";
	private static final String TLS_RSA_WITH_AES_128_CBC_SHA = "TLS_RSA_WITH_AES_128_CBC_SHA";
	
	// Not listed in IANA but encountered
	private static final String SSL_RSA_WITH_RC4_128_SHA = "SSL_RSA_WITH_RC4_128_SHA";
	private static final String SSL_RSA_WITH_3DES_EDE_CBC_SHA = "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
	private static final String SSL_RSA_WITH_RC4_128_MD5 = "SSL_RSA_WITH_RC4_128_MD5";

	

	public static final Protocol PSSLV3  = new Protocol(SSLV3);
	public static final Protocol PTLS1_0 = new Protocol(TLS1_0);
	public static final Protocol PTLS1_1 = new Protocol(TLS1_1);
	public static final Protocol PTLS1_2 = new Protocol(TLS1_2);
	public static final Protocol UNCAT = new Protocol(SUNCAT);
	public static final ArrayList<Protocol> APROTOCOLS = new ArrayList<Protocol>();

	
	static {
		
//        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
		
		Security.addProvider( new BouncyCastleProvider() );
        
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
		OIDMAP.put( "2.5.29.31","CRLDistributionPoints");
		OIDMAP.put( "2.5.29.32","CertificatePolicies");
		OIDMAP.put( "1.3.6.1.4.1.6449.1.2.1.5.1","CertificatePolicyId");
		OIDMAP.put( "2.5.29.32","CertificatePolicies");
		OIDMAP.put( "1.3.6.1.5.5.7.2.1","qualifierID");
		OIDMAP.put( "2.5.29.37","ExtendedKeyUsages");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		
		OIDMAP.put( "2.5.29.14","SubjectKeyIdentifier");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		OIDMAP.put( "2.5.29.15","KeyUsage");
		
		
		
        //APROTOCOLS.add( PSSLV2 );
        APROTOCOLS.add( PSSLV3 );
        APROTOCOLS.add( PTLS1_0 );
        APROTOCOLS.add( PTLS1_1 );
        APROTOCOLS.add( PTLS1_2 );
        APROTOCOLS.add( UNCAT );
       
         
        // Add SSLv2 cipher suites
//        PSSLV2.addCipher(RC4_128_WITH_MD5 );
//        PSSLV2.addCipher(RC4_128_EXPORT40_WITH_MD5 );
//        PSSLV2.addCipher(RC2_128_CBC_WITH_MD5 );
//        PSSLV2.addCipher(RC2_128_CBC_EXPORT40_WITH_MD5 );
//        PSSLV2.addCipher(IDEA_128_CBC_WITH_MD5 );
//        PSSLV2.addCipher(DES_64_CBC_WITH_MD5 );
//        PSSLV2.addCipher(DES_192_EDE3_CBC_WITH_MD5 );
        
        // Add SSLv3 cipher suites
        PSSLV3.addCipher( RSA_WITH_NULL_MD5 );
        PSSLV3.addCipher( RC4_128_WITH_MD5 );
        PSSLV3.addCipher( RSA_WITH_NULL_SHA );
        PSSLV3.addCipher( RSA_EXPORT_WITH_RC4_40_MD5 );
        PSSLV3.addCipher( RSA_WITH_RC4_128_MD5 );
        PSSLV3.addCipher( RSA_WITH_RC4_128_SHA );
        PSSLV3.addCipher( RSA_EXPORT_WITH_RC2_CBC_40_MD5 );
        PSSLV3.addCipher( RSA_WITH_IDEA_CBC_SHA );
        PSSLV3.addCipher( RSA_EXPORT_WITH_DES40_CBC_SHA );
        PSSLV3.addCipher( RSA_WITH_DES_CBC_SHA );
        PSSLV3.addCipher( RSA_WITH_3DES_EDE_CBC_SHA );
        PSSLV3.addCipher( DH_DSS_EXPORT_WITH_DES40_CBC_SHA );
        PSSLV3.addCipher( DH_DSS_WITH_DES_CBC_SHA );
        PSSLV3.addCipher( DH_DSS_WITH_3DES_EDE_CBC_SHA );
        PSSLV3.addCipher( DH_RSA_EXPORT_WITH_DES40_CBC_SHA );
        PSSLV3.addCipher( DH_RSA_WITH_DES_CBC_SHA );
        PSSLV3.addCipher( DH_RSA_WITH_3DES_EDE_CBC_SHA );
        PSSLV3.addCipher( DHE_DSS_EXPORT_WITH_DES40_CBC_SHA );
        PSSLV3.addCipher( DHE_DSS_WITH_DES_CBC_SHA );
        PSSLV3.addCipher( DHE_DSS_WITH_3DES_EDE_CBC_SHA );
        PSSLV3.addCipher( DHE_RSA_EXPORT_WITH_DES40_CBC_SHA );
        PSSLV3.addCipher( DHE_RSA_WITH_DES_CBC_SHA );
        PSSLV3.addCipher( DHE_RSA_WITH_3DES_EDE_CBC_SHA );
        PSSLV3.addCipher( DH_anon_EXPORT_WITH_RC4_40_MD5 );
        PSSLV3.addCipher( DH_anon_WITH_RC4_128_MD5 );
        PSSLV3.addCipher( DH_anon_EXPORT_WITH_DES40_CBC_SHA );
        PSSLV3.addCipher( DH_anon_WITH_DES_CBC_SHA );
        PSSLV3.addCipher( DH_anon_WITH_3DES_EDE_CBC_SHA );
        
        // Add TLS1.0 cipher suites
        PTLS1_0.addCipher( RSA_WITH_NULL_MD5 );
        PTLS1_0.addCipher( RC4_128_WITH_MD5 );
        PTLS1_0.addCipher( RSA_WITH_NULL_SHA );
        PTLS1_0.addCipher( RSA_EXPORT_WITH_RC4_40_MD5 );
        PTLS1_0.addCipher( RSA_WITH_RC4_128_MD5 );
        PTLS1_0.addCipher( RSA_WITH_RC4_128_SHA );
        PTLS1_0.addCipher( RSA_EXPORT_WITH_RC2_CBC_40_MD5 );
        PTLS1_0.addCipher( RSA_WITH_IDEA_CBC_SHA );
        PTLS1_0.addCipher( RSA_EXPORT_WITH_DES40_CBC_SHA );
        PTLS1_0.addCipher( RSA_WITH_DES_CBC_SHA );
        PTLS1_0.addCipher( RSA_WITH_3DES_EDE_CBC_SHA );
        PTLS1_0.addCipher( DH_DSS_EXPORT_WITH_DES40_CBC_SHA );
        PTLS1_0.addCipher( DH_DSS_WITH_DES_CBC_SHA );
        PTLS1_0.addCipher( DH_DSS_WITH_3DES_EDE_CBC_SHA );
        PTLS1_0.addCipher( DH_RSA_EXPORT_WITH_DES40_CBC_SHA );
        PTLS1_0.addCipher( DH_RSA_WITH_DES_CBC_SHA );
        PTLS1_0.addCipher( DH_RSA_WITH_3DES_EDE_CBC_SHA );      
        PTLS1_0.addCipher( DHE_DSS_EXPORT_WITH_DES40_CBC_SHA );
        PTLS1_0.addCipher( DHE_DSS_WITH_DES_CBC_SHA );
        PTLS1_0.addCipher( DHE_DSS_WITH_3DES_EDE_CBC_SHA );
        PTLS1_0.addCipher( DHE_RSA_EXPORT_WITH_DES40_CBC_SHA );
        PTLS1_0.addCipher( DHE_RSA_WITH_DES_CBC_SHA );
        PTLS1_0.addCipher( DHE_RSA_WITH_3DES_EDE_CBC_SHA );
        PTLS1_0.addCipher( DH_anon_EXPORT_WITH_RC4_40_MD5 );
        PTLS1_0.addCipher( DH_anon_WITH_RC4_128_MD5 );
        PTLS1_0.addCipher( DH_anon_EXPORT_WITH_DES40_CBC_SHA );
        PTLS1_0.addCipher( DH_anon_WITH_DES_CBC_SHA );
        PTLS1_0.addCipher( DH_anon_WITH_3DES_EDE_CBC_SHA );
        
        // Add TLS1.1 cipher suites
        PTLS1_1.addCipher( RSA_WITH_AES_128_CBC_SHA );
        PTLS1_1.addCipher( DH_DSS_WITH_AES_128_CBC_SHA );
        PTLS1_1.addCipher( DH_RSA_WITH_AES_128_CBC_SHA );
        PTLS1_1.addCipher( DHE_DSS_WITH_AES_128_CBC_SHA );
        PTLS1_1.addCipher( DHE_RSA_WITH_AES_128_CBC_SHA );
        PTLS1_1.addCipher( DH_anon_WITH_AES_128_CBC_SHA );
        PTLS1_1.addCipher( RSA_WITH_AES_256_CBC_SHA );
        PTLS1_1.addCipher( DH_DSS_WITH_AES_256_CBC_SHA );
        PTLS1_1.addCipher( DH_RSA_WITH_AES_256_CBC_SHA );
        PTLS1_1.addCipher( DHE_DSS_WITH_AES_256_CBC_SHA );
        PTLS1_1.addCipher( DHE_RSA_WITH_AES_256_CBC_SHA );
        PTLS1_1.addCipher( DH_anon_WITH_AES_256_CBC_SHA );
        
        // Add TLS1.2 cipher suites 
        PTLS1_2.addCipher( RSA_WITH_NULL_SHA256 );
        PTLS1_2.addCipher( RSA_WITH_AES_128_CBC_SHA256 );
        PTLS1_2.addCipher( RSA_WITH_AES_256_CBC_SHA256 );
        PTLS1_2.addCipher( DH_DSS_WITH_AES_128_CBC_SHA256 );
        PTLS1_2.addCipher( DH_RSA_WITH_AES_128_CBC_SHA256 );
        PTLS1_2.addCipher( DHE_DSS_WITH_AES_128_CBC_SHA256 );      
        PTLS1_2.addCipher( DHE_RSA_WITH_AES_128_CBC_SHA256 );
        PTLS1_2.addCipher( DH_DSS_WITH_AES_256_CBC_SHA256 );
        PTLS1_2.addCipher( DHE_DSS_WITH_AES_256_CBC_SHA256 );
        PTLS1_2.addCipher( DHE_RSA_WITH_AES_256_CBC_SHA256 );
        PTLS1_2.addCipher( DH_anon_WITH_AES_128_CBC_SHA256 );
        PTLS1_2.addCipher( DH_anon_WITH_AES_256_CBC_SHA256 );
        PTLS1_2.addCipher( TLS_RSA_WITH_AES_128_CBC_SHA );
        
        // Add uncategorized by IANA http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
        UNCAT.addCipher( RSA_WITH_NULL_SHA256 );
        UNCAT.addCipher(TLS_PSK_WITH_RC4_128_SHA);
        UNCAT.addCipher(TLS_PSK_WITH_3DES_EDE_CBC_SHA);
        UNCAT.addCipher(TLS_PSK_WITH_AES_128_CBC_SHA);
        UNCAT.addCipher(TLS_PSK_WITH_AES_256_CBC_SHA );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_RC4_128_SHA );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA );
        UNCAT.addCipher(TLS_DHE_PSK_WITH_AES_128_CBC_SHA );
        UNCAT.addCipher(TLS_DHE_PSK_WITH_AES_256_CBC_SHA);
        UNCAT.addCipher( TLS_RSA_PSK_WITH_RC4_128_SHA );
        UNCAT.addCipher(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA );
        UNCAT.addCipher( TLS_RSA_PSK_WITH_AES_128_CBC_SHA );
        UNCAT.addCipher( TLS_RSA_PSK_WITH_AES_256_CBC_SHA );
        UNCAT.addCipher( TLS_RSA_WITH_SEED_CBC_SHA );
        UNCAT.addCipher( TLS_DH_DSS_WITH_SEED_CBC_SHA );
        UNCAT.addCipher( TLS_DH_RSA_WITH_SEED_CBC_SHA);
        UNCAT.addCipher(TLS_DHE_DSS_WITH_SEED_CBC_SHA);
        UNCAT.addCipher( TLS_DHE_RSA_WITH_SEED_CBC_SHA );
        UNCAT.addCipher(TLS_DH_anon_WITH_SEED_CBC_SHA);
        UNCAT.addCipher( TLS_RSA_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_RSA_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        UNCAT.addCipher( TLS_DH_RSA_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_DH_RSA_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher( TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        UNCAT.addCipher( TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher( TLS_DH_DSS_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_DH_DSS_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher( TLS_DH_anon_WITH_AES_128_GCM_SHA256);
        UNCAT.addCipher( TLS_DH_anon_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher( TLS_PSK_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_PSK_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher( TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 );
        UNCAT.addCipher( TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 );
        UNCAT.addCipher(TLS_PSK_WITH_AES_128_CBC_SHA256);
        UNCAT.addCipher( TLS_PSK_WITH_AES_256_CBC_SHA384 );
        UNCAT.addCipher( TLS_PSK_WITH_NULL_SHA256);
        UNCAT.addCipher( TLS_PSK_WITH_NULL_SHA384);
        UNCAT.addCipher( TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_NULL_SHA256 );
        UNCAT.addCipher( TLS_DHE_PSK_WITH_NULL_SHA384 );
        UNCAT.addCipher( TLS_RSA_PSK_WITH_AES_128_CBC_SHA256);
        UNCAT.addCipher( TLS_RSA_PSK_WITH_AES_256_CBC_SHA384);
        UNCAT.addCipher( TLS_RSA_PSK_WITH_NULL_SHA256 );
        UNCAT.addCipher( TLS_RSA_PSK_WITH_NULL_SHA384);
        UNCAT.addCipher( TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 );
        UNCAT.addCipher( TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 );
        UNCAT.addCipher( TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 );
        UNCAT.addCipher( TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 );
        UNCAT.addCipher( TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 );
        UNCAT.addCipher( TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        UNCAT.addCipher(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 );
        UNCAT.addCipher( TLS_EMPTY_RENEGOTIATION_INFO_SCSV );
        UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_NULL_SHA );
        UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_RC4_128_SHA );
        UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA );
        UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA );
        UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA );
        UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_NULL_SHA );
        UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_RC4_128_SHA );
        UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA );
        UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA );
        UNCAT.addCipher(TLS_ECDH_RSA_WITH_NULL_SHA );
        UNCAT.addCipher( TLS_ECDH_RSA_WITH_RC4_128_SHA );
        UNCAT.addCipher( TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA );
        UNCAT.addCipher( TLS_ECDH_RSA_WITH_AES_128_CBC_SHA );
        UNCAT.addCipher( TLS_ECDH_RSA_WITH_AES_256_CBC_SHA );
        UNCAT.addCipher( TLS_ECDHE_RSA_WITH_NULL_SHA );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_RC4_128_SHA );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDH_anon_WITH_NULL_SHA );
    	UNCAT.addCipher( TLS_ECDH_anon_WITH_RC4_128_SHA );
    	UNCAT.addCipher( TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDH_anon_WITH_AES_128_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDH_anon_WITH_AES_256_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA);
    	UNCAT.addCipher( TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_WITH_AES_128_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_WITH_AES_256_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA );
    	UNCAT.addCipher( TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    	UNCAT.addCipher(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_RC4_128_SHA );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA );
    	UNCAT.addCipher(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384);
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_NULL_SHA );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_NULL_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_NULL_SHA384 );
    	UNCAT.addCipher( TLS_RSA_WITH_ARIA_128_CBC_SHA256);
    	UNCAT.addCipher( TLS_RSA_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384);
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher(TLS_RSA_WITH_ARIA_128_GCM_SHA256);
    	UNCAT.addCipher( TLS_RSA_WITH_ARIA_256_GCM_SHA384);
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher(TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256);
    	UNCAT.addCipher( TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher(TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher(TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384);
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256);
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher(TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher(TLS_PSK_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_PSK_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384);
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_PSK_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_PSK_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 );
    	UNCAT.addCipher(TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
    	UNCAT.addCipher( TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384);
    	UNCAT.addCipher(TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
    	UNCAT.addCipher( TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256);
    	UNCAT.addCipher( TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 );
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256);
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 );
    	UNCAT.addCipher( TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 );
    	UNCAT.addCipher( TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 );
    	UNCAT.addCipher( TLS_RSA_WITH_AES_128_CCM );
    	UNCAT.addCipher(TLS_RSA_WITH_AES_256_CCM );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_AES_128_CCM );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_AES_256_CCM );
    	UNCAT.addCipher(TLS_RSA_WITH_AES_128_CCM_8 );
    	UNCAT.addCipher( TLS_RSA_WITH_AES_256_CCM_8 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_AES_128_CCM_8 );
    	UNCAT.addCipher( TLS_DHE_RSA_WITH_AES_256_CCM_8 );
    	UNCAT.addCipher( TLS_PSK_WITH_AES_128_CCM);
    	UNCAT.addCipher( TLS_PSK_WITH_AES_256_CCM );
    	UNCAT.addCipher( TLS_DHE_PSK_WITH_AES_128_CCM );
    	UNCAT.addCipher(TLS_DHE_PSK_WITH_AES_256_CCM);
    	UNCAT.addCipher( TLS_PSK_WITH_AES_128_CCM_8 );
    	UNCAT.addCipher(TLS_PSK_WITH_AES_256_CCM_8 );
    	UNCAT.addCipher(TLS_PSK_DHE_WITH_AES_128_CCM_8);
    	UNCAT.addCipher(TLS_PSK_DHE_WITH_AES_256_CCM_8);
    	
    	// Not appearing in IANA but encountered http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    	UNCAT.addCipher(TLS_RSA_WITH_AES_128_CBC_SHA );
    	UNCAT.addCipher(SSL_RSA_WITH_RC4_128_SHA);
    	UNCAT.addCipher(SSL_RSA_WITH_3DES_EDE_CBC_SHA);
    	UNCAT.addCipher(SSL_RSA_WITH_RC4_128_MD5);
	}
	
	public static final Protocol[] getClientSupportedProtocols() {
		
		return (Protocol[])APROTOCOLS.toArray(new Protocol[0]);
		
	}
	
	public static String[] getServerSupportedCiphersuites( URL url ) throws Exception {
		
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)factory.createSocket(url.getHost(), url.getDefaultPort());  
		String[] client_supported = socket.getEnabledCipherSuites();
		try { socket.close(); } catch( SocketException e ) {}
		
		ArrayList<String> result = new ArrayList<String>();
		
		for( String cipher : client_supported ) {
			
			try {
				socket = (SSLSocket)factory.createSocket(url.getHost(), url.getDefaultPort()); 
				socket.setEnabledCipherSuites(new String[] { cipher });
				socket.startHandshake();
		        result.add(cipher);
				Thread.sleep((int)(NICE*Math.random()));
			} catch( SSLHandshakeException e ) {
				// Just sink these messages unless we are really interested, too noisy otherwise.
				logger.trace("url="+url.toString(), e);
			} finally {
				try { socket.close(); } catch( SocketException e ) {}
			}
			
		}
		
		return (String[])result.toArray(new String[result.size()]);
	}

	
	// Converts to java.security.  Ugly!
	// http://exampledepot.8waytrips.com/egs/javax.security.cert/ConvertCert.html
	public static java.security.cert.X509Certificate convert(javax.security.cert.X509Certificate cert) {
	    try {
	        byte[] encoded = cert.getEncoded();
	        ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
	        java.security.cert.CertificateFactory cf
	            = java.security.cert.CertificateFactory.getInstance("X.509");
	        return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
	    } catch (javax.security.cert.CertificateEncodingException e) {
			logger.error("",e);
	    } catch (java.security.cert.CertificateException e) {
			logger.error("",e);
	    }
	    return null;
	}
	
	public static final String getStrength(String protocol) {
		
		String clear = "CLEAR(no encryption)";
		String weak = "WEAK";
		String medium = "MEDIUM";
		String strong = "STRONG";
		
		String result = clear;
		
		if (protocol.contains("_NULL_") ) {
			
			result = clear;
			
		} else if ( protocol.contains("DES40") ||
				    protocol.contains("_40_") ||
				    protocol.contains("_EXPORT40_") ) {
		
			result = weak;
		
		} else if ( protocol.contains("_DES_") ||
			    protocol.contains("_DES64_") ||
			    protocol.contains("_DES192_") ) {
	
		result = medium;
		
		} else {
			
			result = strong;
		}
	
	    return result;
		
	}
	
	public static final X509Certificate getServerCertificate(URL url) throws Exception {
		
		X509Certificate[] certs = getServerCertificateChain(url);
		
		return certs[0];
		
	}
	
	public static final X509Certificate[] getServerCertificateChain(URL url) throws Exception {
	   
        HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();
        
        ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
        
        for (Certificate cert : certs) {
        	
            if(cert instanceof X509Certificate) {            	
            	list.add( (X509Certificate)cert );           
            } else {
            	logger.info("Unsupported certificate type.  type="+cert.getClass().getName());
            }
        }
	
        return list.toArray(new X509Certificate[0]);
	}
	
	
	public static final boolean checkTrustedCertificate( X509Certificate[] certs, URL url) throws KeyStoreException, NoSuchAlgorithmException, UnknownHostException, IOException {
		
		boolean valid = false;
		
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)factory.createSocket(url.getHost(), url.getDefaultPort());  
        SSLSession session = socket.getSession();
        String keyexchalgo = getKeyExchangeAlgorithm(session);
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
			        	logger.error( "url="+url.toString(), e);
			        }
			    }
			        
			}
		return valid;
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
	
	
	private static final String getKeyExchangeAlgorithm( SSLSession session ) {
		
		String cipher = session.getCipherSuite().toString();
		
		int i1 = cipher.indexOf('_')+1;
		
		int i2 = cipher.indexOf("_WITH");
		
		String keyexch = cipher.substring(i1, i2);
		
		return keyexch;
		
	}
	
	public static final boolean isSelfSignedCertificate( X509Certificate cert ) {
		
		boolean result = false;
		
		if (cert != null ) {
			
			if ( cert.getIssuerDN().equals(cert.getSubjectDN()) )
				result = true;
			
		}
		
		return result;
		
	}
	   
	   public static final String sha1Fingerprint( byte[] der ) throws NoSuchAlgorithmException {
		   
		   MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		   sha1.update( der );
		   
		   StringBuffer buff = new StringBuffer();
		   buff.append("0x");
		   buff.append(byteArrayToHex(sha1.digest()));
		   
		   return buff.toString();
		   
	   }
	   
	   public static final String md5Fingerprint( byte[] der ) throws NoSuchAlgorithmException {
		   
		   MessageDigest sha1 = MessageDigest.getInstance("MD5");
		   sha1.update( der );
		   
		   StringBuffer buff = new StringBuffer();
		   buff.append("0x");
		   buff.append(byteArrayToHex(sha1.digest()));
		   
		   return buff.toString();
		   
	   }
	   
	   public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a) {
		      sb.append(String.format("%02x", b & 0xff));
		      sb.append(':');
		   }
		   sb.setLength(sb.length()-1);
		   return sb.toString().toUpperCase();
		}

	   public static String getOIDKeyName(String oidkey) {
		   
		   // TODO: Need to figure out a better way to do this.
		   return (OIDMAP.get(oidkey)!=null) ? OIDMAP.get(oidkey) : oidkey;
		   
	   }

	// based upon article.  http://stackoverflow.com/questions/2409618/how-do-i-decode-a-der-encoded-string-in-java
	public static final ASN1Primitive toDERObject(byte[] data) throws IOException
	{
	    ByteArrayInputStream inStream = new ByteArrayInputStream(data);
	    ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
	    
	    ASN1Primitive p = asnInputStream.readObject();
	    
	    asnInputStream.close();
	
	    return p;
	}

	public static final void walkASN1Sequence( ASN1Primitive primitive, StringBuffer buff ) throws IOException {
		
		
	    if (primitive instanceof DEROctetString) {
	    	
	    	ASN1Primitive p = toDERObject(((DEROctetString) primitive).getOctets());
	
	    	walkASN1Sequence(p, buff);
	    	
	    	
	    } else if( primitive instanceof DLSequence ) {
	    	
	    	DLSequence dl = (DLSequence)primitive;
	    	
	    	for (int i=0; i < dl.size() ; i++ ) {
	    		
	    		ASN1Primitive p = dl.getObjectAt(i).toASN1Primitive();
	    		
	    		walkASN1Sequence( p, buff );            		
	    		
	    	}
	    	
	    } else if( primitive instanceof DERSequence ) {
	    	
	    	DERSequence ds = (DERSequence)primitive;
	    	
	    	for (int i=0; i < ds.size() ; i++ ) {
	    		
	    		ASN1Primitive p = ds.getObjectAt(i).toASN1Primitive();
	    		
	    		walkASN1Sequence( p, buff );            		
	    		
	    	}
	    	
	    // Assistance by https://svn.cesecore.eu/svn/ejbca/branches/Branch_3_11/ejbca/conf/extendedkeyusage.properties
	    } else if (primitive instanceof ASN1ObjectIdentifier ) {
	    	
	    	ASN1ObjectIdentifier i = (ASN1ObjectIdentifier)primitive;
	    	
	    	String kn = CipherSuiteUtil.getOIDKeyName(i.toString());
	    	
	    	if ( kn.equals("2.5.29.37.0") ) {
	    		buff.append( "anyextendedkeyusage ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.1") ) {
	    		buff.append( "serverauth ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.2") ) {
	    		buff.append( "clientauth ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.3") ) {
	    		buff.append( "codesigning ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.4") ) {
	    		buff.append( "emailprotection ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.8") ) {
	    		buff.append( "timestamping ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.9") ) {
	    		buff.append( "ocspsigner ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.15") ) {
	    		buff.append( "scvpserver ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.16") ) {
	    		buff.append( "scvpclient ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.22") ) {
	    		buff.append( "eku_pkix_sshserver ");
	    		
	    	} else if (kn.equals("1.3.6.1.5.5.7.3.21") ) {
	    		buff.append( "eku_pkix_sshclient ");
	    		
	    	} else {	
	    		    	
	    		buff.append( CipherSuiteUtil.getOIDKeyName(i.toString()) );
	    		buff.append( "=" );
	    	
	    	}
	    	
	    } else if (primitive instanceof DERIA5String ) {
	    	
	    	DERIA5String ia5string = (DERIA5String)primitive;
	    	buff.append( ia5string.getString() );
	    	buff.append( ' ' );
	    	
	    } else if (primitive instanceof DERBitString ) {
	    	
	    	DERBitString bitstring = (DERBitString)primitive;
	    	int v = bitstring.intValue();
	    
		    	
		    if( (v & 0x1) == 1 )
		    	buff.append( "digitial_signature ");
		    
		    if ((v & 0x2) == 2)
		    	buff.append( "nonrepudiation ");
		    	
		    if ((v & 0x4) == 4)
		    	buff.append( "keyencipherment ");

			if ((v & 0x8) == 8)
		    	buff.append( "dataencipherment ");

			if ((v & 0x16) == 16)
		    	buff.append( "keyagreement ");

			if ((v & 0x32) == 32)
		    	buff.append( "keycertsign ");
		    	
			if ((v & 0x64) == 64)
		    	buff.append( "crlsign ");
		    	
			if ((v & 0x128) == 128)
		    	buff.append( "encipheronly ");
		    		
			if ((v & 0x256) == 256)
		    	buff.append( "decipherOnly ");

	    	
	    } else if (primitive instanceof ASN1Boolean ) {
	    	
	    	ASN1Boolean ans1boolean = (ASN1Boolean)primitive;
	    	buff.append( ans1boolean.isTrue() ? "TRUE" : "FALSE" );
	    	buff.append( ' ' );
	    	
	    } else if (primitive instanceof ASN1Integer ) {
	    	
	    	ASN1Integer ans1int = (ASN1Integer)primitive;
	    	buff.append( ans1int.toString() );
	    	buff.append( ' ' );
	    	
	    // Assistance fm http://stackoverflow.com/questions/16058889/java-bouncy-castle-ocsp-url
	    } else if (primitive instanceof DERTaggedObject ) {
	    	
	    	DERTaggedObject t = (DERTaggedObject)primitive;
	    	byte[] b = t.getEncoded();
            int length = b[1];
	    	
	    	if( t.getTagNo() == 6 ) { // Several
	            buff.append( new String(b, 2, length) );
	            buff.append( " | ");
	    	} else if( t.getTagNo() == 2 ) { //SubjectAlternativeName
		        buff.append( new String(b, 2, length) );
		        buff.append( " | ");
	    	} else if( t.getTagNo() == 0 ) { // CRLDistributionPoints	
	    		ASN1Primitive p = t.getObject();
	    		walkASN1Sequence( p, buff ); 
	    	} else {
	    		
	            buff.append( "type="+t.getTagNo()+" ");
	            String hex = CipherSuiteUtil.byteArrayToHex(b);
	            buff.append( " hex="+hex );
	            buff.append( " string="+new String(b, 2, length) );
	            buff.append( " | ");
	    		
	    		logger.warn("Unhandled DERTaggedObject type.  Printing raw info., type="+t.getTagNo() );
	    	}
	    	
	    } else {
	    	
            buff.append( "Unhandled type, see log" );
            buff.append( " | ");
	    	
    		logger.error("Unhandled primitive data type, type="+primitive.getClass().getName() );
	    	
	    }
	    
	}

	// based upon article.  http://stackoverflow.com/questions/2409618/how-do-i-decode-a-der-encoded-string-in-java
	public static final String getExtensionValue(X509Certificate X509Certificate, String oid) throws IOException {
		
		StringBuffer buff = new StringBuffer();
		
		buff.append('[');
		
	    byte[] extensionValue = X509Certificate.getExtensionValue(oid);
	
	    if (extensionValue == null)  return null;
	    	
	    walkASN1Sequence( toDERObject(extensionValue), buff);
	    
	    if( buff.toString().endsWith("| "))
	    	buff.setLength(buff.length()-2);
		
	    buff.append(']');
	
	    return buff.toString();
	
	}
	   

}


