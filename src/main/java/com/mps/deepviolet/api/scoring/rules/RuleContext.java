package com.mps.deepviolet.api.scoring.rules;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IRevocationStatus;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;
import com.mps.deepviolet.api.tls.ServerHello;
import com.mps.deepviolet.api.tls.TlsExtension;
import com.mps.deepviolet.api.tls.TlsMetadata;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds a property namespace from TLS metadata and provides property resolution
 * for the expression evaluator.
 *
 * <p>Exposes: {@code session.*}, {@code cert.*}, {@code revocation.*},
 * {@code protocols} (Set), {@code ciphers} (List of maps).</p>
 */
public class RuleContext {

	private static final Logger logger = LoggerFactory.getLogger(RuleContext.class);

	private final Map<String, Object> rootProperties = new HashMap<>();
	private final Map<String, List<String>> headers;
	private final List<String> warnings = new ArrayList<>();

	private RuleContext(Map<String, List<String>> headers) {
		this.headers = headers;
	}

	/**
	 * Warnings collected during context construction (data-gathering failures).
	 */
	public List<String> getWarnings() {
		return List.copyOf(warnings);
	}

	/**
	 * Build a RuleContext from engine data.
	 */
	public static RuleContext from(IEngine engine) throws DeepVioletException {
		ISession session = engine.getSession();
		IX509Certificate cert = engine.getCertificate();
		ICipherSuite[] cipherSuites = engine.getCipherSuites();
		Map<String, List<String>> headers = session.getHttpResponseHeaders();
		IRevocationStatus revStatus = cert != null ? cert.getRevocationStatus() : null;

		RuleContext ctx = new RuleContext(headers);

		// Build session properties
		Map<String, Object> sessionProps = new LinkedHashMap<>();
		sessionProps.put("negotiated_protocol",
				session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_PROTOCOL));
		sessionProps.put("negotiated_cipher_suite",
				session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_CIPHER_SUITE));

		String compression = session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.DEFLATE_COMPRESSION);
		sessionProps.put("compression_enabled", "true".equalsIgnoreCase(compression));

		String clientAuthReq = session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.CLIENT_AUTH_REQ);
		sessionProps.put("client_auth_required", "true".equalsIgnoreCase(clientAuthReq));

		String clientAuthWant = session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.CLIENT_AUTH_WANT);
		sessionProps.put("client_auth_wanted", "true".equalsIgnoreCase(clientAuthWant));

		sessionProps.put("headers_available", headers != null);

		// TLS fingerprint
		String fingerprint = null;
		try {
			fingerprint = engine.getTlsFingerprint();
		} catch (DeepVioletException e) {
			logger.debug("TLS fingerprint unavailable: {}", e.getMessage());
			ctx.warnings.add("RuleContext: TLS fingerprint unavailable: " + e.getMessage());
		}
		sessionProps.put("fingerprint", fingerprint);

		// Derive honors_client_cipher_preference from fingerprint probes 1 vs 2
		Boolean honorsClientCipherPref = null;
		if (fingerprint != null) {
			TlsServerFingerprint.FingerprintComponents fp =
					TlsServerFingerprint.parse(fingerprint);
			if (fp != null && fp.probeSucceeded(1) && fp.probeSucceeded(2)) {
				String cipher1 = fp.getCipherChar(1);
				String cipher2 = fp.getCipherChar(2);
				honorsClientCipherPref = !cipher1.equals(cipher2);
			}
		}
		sessionProps.put("honors_client_cipher_preference", honorsClientCipherPref);

		// Derive negotiated cipher strength
		String negotiatedCipher = (String) sessionProps.get("negotiated_cipher_suite");
		String negotiatedStrength = findCipherStrength(cipherSuites, negotiatedCipher);
		sessionProps.put("negotiated_cipher_strength", negotiatedStrength);

		// Fallback SCSV support
		Boolean fallbackScsv = null;
		try {
			fallbackScsv = engine.getFallbackScsvSupported();
		} catch (DeepVioletException e) {
			logger.debug("Fallback SCSV check unavailable: {}", e.getMessage());
			ctx.warnings.add("RuleContext: SCSV probe failed: " + e.getMessage());
		}
		sessionProps.put("fallback_scsv_supported", fallbackScsv);

		// TLS metadata from raw handshake (renegotiation_info, ALPN, early_data)
		TlsMetadata tlsMeta = null;
		try {
			tlsMeta = engine.getTlsMetadata();
		} catch (DeepVioletException e) {
			logger.debug("TLS metadata unavailable: {}", e.getMessage());
			ctx.warnings.add("RuleContext: TLS metadata unavailable: " + e.getMessage());
		}
		boolean tlsMetaAvailable = tlsMeta != null && tlsMeta.getServerHello() != null;
		sessionProps.put("tls_metadata_available", tlsMetaAvailable);

		if (tlsMetaAvailable) {
			ServerHello serverHello = tlsMeta.getServerHello();
			sessionProps.put("renegotiation_info_present",
					serverHello.hasExtension(TlsExtension.RENEGOTIATION_INFO));
			sessionProps.put("early_data_accepted",
					serverHello.hasExtension(TlsExtension.EARLY_DATA));

			// Parse ALPN extension
			byte[] alpnData = serverHello.getExtensionData(TlsExtension.ALPN);
			String alpnNegotiated = parseAlpn(alpnData);
			sessionProps.put("alpn_negotiated", alpnNegotiated);

			// ServerKeyExchange parameters
			com.mps.deepviolet.api.tls.ServerKeyExchange ske = tlsMeta.getServerKeyExchange();
			if (ske != null) {
				sessionProps.put("kex_type", ske.getKexType().name());
				sessionProps.put("dh_param_size", (long) ske.getDhPrimeSizeBits());
				sessionProps.put("ec_curve", ske.getEcCurveName());
			}
		}

		ctx.rootProperties.put("session", sessionProps);

		// Build protocols set
		Set<String> protocols = new HashSet<>();
		if (cipherSuites != null) {
			for (ICipherSuite cs : cipherSuites) {
				String proto = cs.getHandshakeProtocol();
				if (proto != null) protocols.add(proto);
			}
		}
		ctx.rootProperties.put("protocols", protocols);

		// Build ciphers list (list of maps with name, strength, protocol)
		List<Map<String, Object>> cipherList = new ArrayList<>();
		if (cipherSuites != null) {
			for (ICipherSuite cs : cipherSuites) {
				Map<String, Object> cipherMap = new LinkedHashMap<>();
				cipherMap.put("name", cs.getSuiteName());
				cipherMap.put("strength", cs.getStrengthEvaluation());
				cipherMap.put("protocol", cs.getHandshakeProtocol());
				cipherList.add(cipherMap);
			}
		}
		ctx.rootProperties.put("ciphers", cipherList);

		// Build certificate properties
		if (cert != null) {
			Map<String, Object> certProps = new LinkedHashMap<>();
			certProps.put("validity_state",
					cert.getValidityState() != null ? cert.getValidityState().name() : null);
			certProps.put("trust_state",
					cert.getTrustState() != null ? cert.getTrustState().name() : null);
			certProps.put("self_signed", cert.isSelfSignedCertificate());
			certProps.put("java_root", cert.isJavaRootCertificate());
			certProps.put("key_algorithm", cert.getPublicKeyAlgorithm());
			certProps.put("key_size", (long) cert.getPublicKeySize());
			certProps.put("key_curve", cert.getPublicKeyCurve());
			certProps.put("signing_algorithm", cert.getSigningAlgorithm());
			certProps.put("days_until_expiration", cert.getDaysUntilExpiration());

			IX509Certificate[] chain = cert.getCertificateChain();
			certProps.put("chain_length", chain != null ? (long) chain.length : 0L);

			List<String> sans = cert.getSubjectAlternativeNames();
			certProps.put("san_count", sans != null ? (long) sans.size() : 0L);
			certProps.put("sans", sans != null ? sans : List.of());
			certProps.put("version", (long) cert.getCertificateVersion());

			// Check for wildcard SANs
			boolean hasWildcard = false;
			if (sans != null) {
				for (String san : sans) {
					if (san != null && san.startsWith("*.")) {
						hasWildcard = true;
						break;
					}
				}
			}
			certProps.put("has_wildcard_san", hasWildcard);

			ctx.rootProperties.put("cert", certProps);
		}

		// Build revocation properties
		Map<String, Object> revProps = new LinkedHashMap<>();
		revProps.put("available", revStatus != null);
		if (revStatus != null) {
			revProps.put("ocsp_status",
					revStatus.getOcspStatus() != null ? revStatus.getOcspStatus().name() : null);
			revProps.put("crl_status",
					revStatus.getCrlStatus() != null ? revStatus.getCrlStatus().name() : null);
			revProps.put("ocsp_stapling_present", revStatus.isOcspStaplingPresent());
			revProps.put("must_staple_present", revStatus.isMustStaplePresent());
			revProps.put("sct_count", (long) revStatus.getSctCount());
			revProps.put("embedded_sct_count", (long) revStatus.getEmbeddedSctCount());
		}
		ctx.rootProperties.put("revocation", revProps);

		// Build DNS security properties
		Map<String, Object> dnsProps = new LinkedHashMap<>();
		try {
			com.mps.deepviolet.api.IDnsStatus dnsStatus = engine.getDnsStatus();
			if (dnsStatus != null && dnsStatus.isAvailable()) {
				dnsProps.put("available", true);
				dnsProps.put("has_caa_records", dnsStatus.hasCaaRecords());
				dnsProps.put("has_tlsa_records", dnsStatus.hasTlsaRecords());
			} else {
				dnsProps.put("available", false);
			}
		} catch (DeepVioletException e) {
			logger.debug("DNS status unavailable: {}", e.getMessage());
			ctx.warnings.add("RuleContext: DNS lookup failed: " + e.getMessage());
			dnsProps.put("available", false);
		}
		ctx.rootProperties.put("dns", dnsProps);

		return ctx;
	}

	/**
	 * Export this context as a serializable map (for JSON persistence).
	 * Converts Set values to List for clean JSON round-tripping.
	 */
	public Map<String, Object> toSerializableMap() {
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("context_version", "1.0");
		map.put("properties", convertSetsToLists(new LinkedHashMap<>(rootProperties)));
		map.put("headers", headers != null ? new LinkedHashMap<>(headers) : null);
		map.put("warnings", List.copyOf(warnings));
		return map;
	}

	/**
	 * Reconstruct a RuleContext from a serialized map.
	 */
	@SuppressWarnings("unchecked")
	public static RuleContext fromSerializableMap(Map<String, Object> map) {
		Map<String, Object> props = (Map<String, Object>) map.get("properties");
		Map<String, List<String>> hdrs = (Map<String, List<String>>) map.get("headers");
		RuleContext ctx = fromMaps(props != null ? props : Map.of(), hdrs);
		List<String> savedWarnings = (List<String>) map.get("warnings");
		if (savedWarnings != null) ctx.warnings.addAll(savedWarnings);
		return ctx;
	}

	/**
	 * Recursively convert Set values to List for JSON serialization.
	 */
	@SuppressWarnings("unchecked")
	private static Object convertSetsToLists(Object value) {
		if (value instanceof Set<?> set) return new ArrayList<>(set);
		if (value instanceof Map<?, ?> map) {
			Map<String, Object> result = new LinkedHashMap<>();
			for (Map.Entry<?, ?> e : map.entrySet()) {
				result.put((String) e.getKey(), convertSetsToLists(e.getValue()));
			}
			return result;
		}
		return value;
	}

	/**
	 * Build a RuleContext from raw property maps (for testing).
	 */
	public static RuleContext fromMaps(Map<String, Object> rootProps, Map<String, List<String>> headers) {
		RuleContext ctx = new RuleContext(headers);
		ctx.rootProperties.putAll(rootProps);
		return ctx;
	}

	/**
	 * Resolve a dotted property path.
	 */
	@SuppressWarnings("unchecked")
	public Object resolve(List<String> path) {
		if (path.isEmpty()) return null;

		Object current = rootProperties.get(path.get(0));
		for (int i = 1; i < path.size(); i++) {
			if (current == null) return null;
			if (current instanceof Map<?, ?> map) {
				current = map.get(path.get(i));
			} else {
				return null;
			}
		}
		return current;
	}

	/**
	 * Get an HTTP header value (case-insensitive).
	 */
	public String getHeader(String name) {
		if (headers == null || name == null) return null;
		for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
			if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
				List<String> values = entry.getValue();
				if (values != null && !values.isEmpty()) {
					return values.get(0);
				}
			}
		}
		return null;
	}

	/**
	 * Parse ALPN extension data from ServerHello.
	 * Format: 2-byte list length + (1-byte name length + name)*
	 */
	private static String parseAlpn(byte[] data) {
		if (data == null || data.length < 4) return null;
		int listLen = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
		if (listLen < 2 || 2 + listLen > data.length) return null;
		int nameLen = data[2] & 0xFF;
		if (nameLen < 1 || 3 + nameLen > data.length) return null;
		return new String(data, 3, nameLen, java.nio.charset.StandardCharsets.US_ASCII);
	}

	private static String findCipherStrength(ICipherSuite[] ciphers, String negotiatedCipher) {
		if (ciphers == null || negotiatedCipher == null) return null;
		for (ICipherSuite cipher : ciphers) {
			String name = cipher.getSuiteName();
			if (name != null && negotiatedCipher.contains(name.trim())) {
				return cipher.getStrengthEvaluation();
			}
		}
		return null;
	}
}
