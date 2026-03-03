package com.mps.deepviolet.api;

import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mps.deepviolet.util.DerParser;
import com.mps.deepviolet.util.OcspClient;
import com.mps.deepviolet.util.X509Extensions;

/**
 * Performs certificate revocation and transparency checks.
 * Each check is independent and fail-safe.
 */
class RevocationChecker {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.RevocationChecker");
	private static final int NETWORK_TIMEOUT_MS = 8000;
	private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_INSTANT;

	private RevocationChecker() {}

	/**
	 * Run all revocation/transparency checks for a certificate.
	 * @param cert The certificate to check
	 * @param issuer The issuer certificate (needed for OCSP)
	 * @return Populated revocation status
	 */
	static RevocationStatus check(X509Certificate cert, X509Certificate issuer) {
		RevocationStatus status = new RevocationStatus(cert.getSubjectX500Principal().toString());
		checkOcsp(cert, issuer, status);
		checkCrl(cert, status);
		checkMustStaple(cert, status);
		checkEmbeddedSct(cert, status);
		// TLS Extension SCTs: Java JSSE does not expose raw TLS extensions (signed_certificate_timestamp, type 18)
		// Set to -1 to indicate N/A due to platform limitation
		status.setTlsExtensionSctCount(-1);
		status.setTlsExtensionSctDetails(new String[0]);
		return status;
	}

	/**
	 * Check OneCRL for a certificate. Called separately since it's a single network call for all certs.
	 */
	static void checkOneCrl(X509Certificate cert, RevocationStatus status) {
		HttpURLConnection conn = null;
		try {
			long start = System.nanoTime();
			URL oneCrlUrl = URI.create(
				"https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records"
			).toURL();

			conn = (HttpURLConnection) oneCrlUrl.openConnection();
			conn.setConnectTimeout(NETWORK_TIMEOUT_MS);
			conn.setReadTimeout(NETWORK_TIMEOUT_MS);
			conn.setRequestProperty("Accept", "application/json");

			if (conn.getResponseCode() != 200) {
				status.setOneCrlStatus(IRevocationStatus.RevocationResult.ERROR);
				status.setOneCrlErrorMessage("HTTP " + conn.getResponseCode());
				return;
			}

			JsonObject root;
			try (java.io.InputStreamReader reader = new java.io.InputStreamReader(conn.getInputStream())) {
				root = JsonParser.parseReader(reader).getAsJsonObject();
			}
			JsonElement data = root.has("data") ? root.get("data") : root;

			BigInteger serial = cert.getSerialNumber();

			boolean found = false;
			if (data.isJsonArray()) {
				JsonArray dataArray = data.getAsJsonArray();
				for (JsonElement el : dataArray) {
					JsonObject record = el.getAsJsonObject();
					if (record.has("issuerName") && record.has("serialNumber")) {
						String recSerial = record.get("serialNumber").getAsString();
						// OneCRL stores serial as base64 or hex
						try {
							BigInteger recSerialNum = new BigInteger(recSerial, 16);
							if (recSerialNum.equals(serial)) {
								found = true;
								break;
							}
						} catch (NumberFormatException ignored) {
							// Try next record
						}
					}
				}
			}

			long elapsed = (System.nanoTime() - start) / 1_000_000;
			status.setOneCrlStatus(found
				? IRevocationStatus.RevocationResult.REVOKED
				: IRevocationStatus.RevocationResult.GOOD);
			if (!found) {
				status.setOneCrlErrorMessage("Not found in OneCRL (checked in " + elapsed + "ms)");
			}

		} catch (Exception e) {
			logger.error("OneCRL check failed", e);
			status.setOneCrlStatus(IRevocationStatus.RevocationResult.ERROR);
			status.setOneCrlErrorMessage(e.getMessage());
		} finally {
			if (conn != null) conn.disconnect();
		}
	}

	/**
	 * Parse and check a stapled OCSP response for certificate revocation status.
	 * Note: OCSP stapling is now captured via {@code DeepVioletFactory.initializeSession()}
	 * and SCTs are extracted via {@link #checkOcspStaplingScts}. This method remains
	 * available for full OCSP stapling status checks when needed.
	 * @param stapledResponse Raw OCSP response bytes from the TLS handshake
	 * @param cert The certificate to check
	 * @param issuer The issuer certificate
	 * @param status The revocation status object to update
	 */
	static void checkOcspStapling(byte[] stapledResponse, X509Certificate cert,
								   X509Certificate issuer, RevocationStatus status) {
		if (stapledResponse == null || stapledResponse.length == 0) {
			status.setOcspStaplingPresent(false);
			return;
		}
		status.setOcspStaplingPresent(true);
		try {
			// Parse the OCSP response using DerParser
			DerParser.DerValue ocspResp = DerParser.parse(stapledResponse);
			List<DerParser.DerValue> respParts = ocspResp.getSequence();

			if (respParts.isEmpty()) {
				status.setStapledOcspStatus(IRevocationStatus.RevocationResult.ERROR);
				return;
			}

			// Response status
			int responseStatus = respParts.get(0).getIntValue();
			if (responseStatus != OcspClient.OCSP_SUCCESSFUL) {
				status.setStapledOcspStatus(IRevocationStatus.RevocationResult.ERROR);
				return;
			}

			if (respParts.size() < 2) {
				status.setStapledOcspStatus(IRevocationStatus.RevocationResult.ERROR);
				return;
			}

			// Parse the BasicOCSPResponse to get certificate status
			OcspClient.Status certStatus = parseStapledOcspStatus(respParts.get(1));
			switch (certStatus) {
				case GOOD:
					status.setStapledOcspStatus(IRevocationStatus.RevocationResult.GOOD);
					break;
				case REVOKED:
					status.setStapledOcspStatus(IRevocationStatus.RevocationResult.REVOKED);
					break;
				default:
					status.setStapledOcspStatus(IRevocationStatus.RevocationResult.UNKNOWN);
			}

		} catch (Exception e) {
			logger.error("OCSP stapling parse failed", e);
			status.setStapledOcspStatus(IRevocationStatus.RevocationResult.ERROR);
		}
	}

	/**
	 * Parse stapled OCSP response to extract certificate status.
	 */
	private static OcspClient.Status parseStapledOcspStatus(DerParser.DerValue responseBytesTagged) {
		try {
			DerParser.DerValue responseBytesSeq = responseBytesTagged.getTaggedObject();
			List<DerParser.DerValue> rbParts = responseBytesSeq.getSequence();

			if (rbParts.size() < 2) {
				return OcspClient.Status.ERROR;
			}

			// Parse BasicOCSPResponse
			byte[] basicRespBytes = rbParts.get(1).getOctetString();
			DerParser.DerValue basicResp = DerParser.parse(basicRespBytes);
			List<DerParser.DerValue> basicParts = basicResp.getSequence();

			if (basicParts.isEmpty()) {
				return OcspClient.Status.ERROR;
			}

			// Parse ResponseData
			List<DerParser.DerValue> rdParts = basicParts.get(0).getSequence();
			int idx = 0;

			// Skip version if present
			if (rdParts.get(idx).isContextSpecific() && rdParts.get(idx).getContextTag() == 0) {
				idx++;
			}
			// Skip responderID and producedAt
			idx += 2;

			// responses (SEQUENCE OF SingleResponse)
			if (idx < rdParts.size()) {
				List<DerParser.DerValue> responses = rdParts.get(idx).getSequence();
				if (!responses.isEmpty()) {
					List<DerParser.DerValue> srParts = responses.get(0).getSequence();
					if (srParts.size() >= 2) {
						DerParser.DerValue certStatusVal = srParts.get(1);
						if (certStatusVal.isContextSpecific()) {
							int tag = certStatusVal.getContextTag();
							switch (tag) {
								case 0: return OcspClient.Status.GOOD;
								case 1: return OcspClient.Status.REVOKED;
								case 2: return OcspClient.Status.UNKNOWN;
							}
						} else {
							return OcspClient.Status.GOOD;
						}
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to parse stapled OCSP status", e);
		}
		return OcspClient.Status.UNKNOWN;
	}

	/**
	 * Perform an OCSP check against the certificate's designated OCSP responder.
	 * @param cert The certificate to check
	 * @param issuer The issuer certificate (needed to build the OCSP request)
	 * @param status The revocation status object to update
	 */
	private static void checkOcsp(X509Certificate cert, X509Certificate issuer, RevocationStatus status) {
		try {
			String ocspUrl = X509Extensions.getOcspUrl(cert);
			if (ocspUrl == null) {
				status.setOcspStatus(IRevocationStatus.RevocationResult.NOT_CHECKED);
				status.setOcspErrorMessage("No OCSP responder URL in certificate");
				return;
			}
			status.setOcspResponderUrl(ocspUrl);

			// Use OcspClient to perform the check
			OcspClient client = new OcspClient();
			OcspClient.OcspResponse ocspResponse = client.check(cert, issuer, ocspUrl);

			status.setOcspResponseTimeMs(ocspResponse.responseTimeMs);

			// Map OcspClient.Status to RevocationResult
			switch (ocspResponse.status) {
				case GOOD:
					status.setOcspStatus(IRevocationStatus.RevocationResult.GOOD);
					break;
				case REVOKED:
					status.setOcspStatus(IRevocationStatus.RevocationResult.REVOKED);
					break;
				case UNKNOWN:
					status.setOcspStatus(IRevocationStatus.RevocationResult.UNKNOWN);
					break;
				case ERROR:
					status.setOcspStatus(IRevocationStatus.RevocationResult.ERROR);
					status.setOcspErrorMessage(ocspResponse.errorMessage);
					break;
				default:
					status.setOcspStatus(IRevocationStatus.RevocationResult.NOT_CHECKED);
			}

			// Signature validation
			if (ocspResponse.signatureValid != null) {
				status.setOcspSignatureValid(ocspResponse.signatureValid);
			}

			// Timestamps
			if (ocspResponse.thisUpdate != null) {
				status.setOcspThisUpdate(formatDate(ocspResponse.thisUpdate));
			}
			if (ocspResponse.nextUpdate != null) {
				status.setOcspNextUpdate(formatDate(ocspResponse.nextUpdate));
			}

		} catch (Exception e) {
			logger.error("OCSP check failed", e);
			status.setOcspStatus(IRevocationStatus.RevocationResult.ERROR);
			status.setOcspErrorMessage(e.getMessage());
		}
	}

	/**
	 * Download and check the CRL distribution point for certificate revocation.
	 * @param cert The certificate to check
	 * @param status The revocation status object to update
	 */
	private static void checkCrl(X509Certificate cert, RevocationStatus status) {
		HttpURLConnection conn = null;
		try {
			String crlUrl = X509Extensions.getCrlUrl(cert);
			if (crlUrl == null) {
				status.setCrlStatus(IRevocationStatus.RevocationResult.NOT_CHECKED);
				status.setCrlErrorMessage("No CRL distribution point in certificate");
				return;
			}
			status.setCrlDistributionPoint(crlUrl);

			long start = System.nanoTime();
			conn = (HttpURLConnection) URI.create(crlUrl).toURL().openConnection();
			conn.setConnectTimeout(NETWORK_TIMEOUT_MS);
			conn.setReadTimeout(NETWORK_TIMEOUT_MS);

			byte[] crlBytes;
			try (java.io.InputStream is = conn.getInputStream()) {
				crlBytes = is.readAllBytes();
			}
			long elapsed = (System.nanoTime() - start) / 1_000_000;
			status.setCrlResponseTimeMs(elapsed);
			status.setCrlSizeBytes(crlBytes.length);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));

			if (crl.isRevoked(cert)) {
				status.setCrlStatus(IRevocationStatus.RevocationResult.REVOKED);
			} else {
				status.setCrlStatus(IRevocationStatus.RevocationResult.GOOD);
			}

			if (crl.getThisUpdate() != null) {
				status.setCrlThisUpdate(formatDate(crl.getThisUpdate()));
			}
			if (crl.getNextUpdate() != null) {
				status.setCrlNextUpdate(formatDate(crl.getNextUpdate()));
			}

		} catch (Exception e) {
			logger.error("CRL check failed", e);
			status.setCrlStatus(IRevocationStatus.RevocationResult.ERROR);
			status.setCrlErrorMessage(e.getMessage());
		} finally {
			if (conn != null) conn.disconnect();
		}
	}

	/**
	 * Check whether the certificate has the OCSP Must-Staple extension.
	 * @param cert The certificate to check
	 * @param status The revocation status object to update
	 */
	private static void checkMustStaple(X509Certificate cert, RevocationStatus status) {
		status.setMustStaplePresent(X509Extensions.hasMustStaple(cert));
	}

	/**
	 * Check for embedded SCTs in the certificate extension (OID 1.3.6.1.4.1.11129.2.4.2).
	 */
	private static void checkEmbeddedSct(X509Certificate cert, RevocationStatus status) {
		try {
			List<X509Extensions.SignedCertificateTimestamp> scts = X509Extensions.getScts(cert);

			if (scts.isEmpty()) {
				status.setEmbeddedSctCount(0);
				status.setEmbeddedSctDetails(new String[0]);
				return;
			}

			List<String> sctDetailsList = new ArrayList<>();
			for (X509Extensions.SignedCertificateTimestamp sct : scts) {
				sctDetailsList.add(sct.toString());
			}

			status.setEmbeddedSctCount(sctDetailsList.size());
			status.setEmbeddedSctDetails(sctDetailsList.toArray(new String[0]));

		} catch (Exception e) {
			logger.error("Embedded SCT parsing failed", e);
			status.setEmbeddedSctCount(0);
			status.setEmbeddedSctDetails(new String[0]);
		}
	}

	/**
	 * Check for SCTs in an OCSP stapling response (OID 1.3.6.1.4.1.11129.2.4.5).
	 * @param stapledResponse The raw OCSP response bytes from TLS handshake
	 * @param status The revocation status object to update
	 */
	static void checkOcspStaplingScts(byte[] stapledResponse, RevocationStatus status) {
		if (stapledResponse == null || stapledResponse.length == 0) {
			status.setOcspStaplingSctCount(0);
			status.setOcspStaplingSctDetails(new String[0]);
			return;
		}

		try {
			// Parse the OCSP response using DerParser
			DerParser.DerValue ocspResp = DerParser.parse(stapledResponse);
			List<DerParser.DerValue> respParts = ocspResp.getSequence();

			if (respParts.isEmpty()) {
				status.setOcspStaplingSctCount(0);
				status.setOcspStaplingSctDetails(new String[0]);
				return;
			}

			// Response status
			int responseStatus = respParts.get(0).getIntValue();
			if (responseStatus != OcspClient.OCSP_SUCCESSFUL) {
				status.setOcspStaplingSctCount(0);
				status.setOcspStaplingSctDetails(new String[0]);
				return;
			}

			if (respParts.size() < 2) {
				status.setOcspStaplingSctCount(0);
				status.setOcspStaplingSctDetails(new String[0]);
				return;
			}

			// Parse to find SCT extension in single response
			byte[] sctExtValue = extractSctExtensionFromOcspResponse(respParts.get(1));
			if (sctExtValue == null) {
				status.setOcspStaplingSctCount(0);
				status.setOcspStaplingSctDetails(new String[0]);
				return;
			}

			List<X509Extensions.SignedCertificateTimestamp> scts = X509Extensions.parseSctList(sctExtValue);
			List<String> sctDetailsList = new ArrayList<>();
			for (X509Extensions.SignedCertificateTimestamp sct : scts) {
				sctDetailsList.add(sct.toString());
			}

			status.setOcspStaplingSctCount(sctDetailsList.size());
			status.setOcspStaplingSctDetails(sctDetailsList.toArray(new String[0]));

		} catch (Exception e) {
			logger.error("OCSP stapling SCT parsing failed", e);
			status.setOcspStaplingSctCount(0);
			status.setOcspStaplingSctDetails(new String[0]);
		}
	}

	/**
	 * Extract SCT extension value from OCSP response.
	 */
	private static byte[] extractSctExtensionFromOcspResponse(DerParser.DerValue responseBytesTagged) {
		try {
			DerParser.DerValue responseBytesSeq = responseBytesTagged.getTaggedObject();
			List<DerParser.DerValue> rbParts = responseBytesSeq.getSequence();

			if (rbParts.size() < 2) {
				return null;
			}

			// Parse BasicOCSPResponse
			byte[] basicRespBytes = rbParts.get(1).getOctetString();
			DerParser.DerValue basicResp = DerParser.parse(basicRespBytes);
			List<DerParser.DerValue> basicParts = basicResp.getSequence();

			if (basicParts.isEmpty()) {
				return null;
			}

			// Parse ResponseData
			List<DerParser.DerValue> rdParts = basicParts.get(0).getSequence();
			int idx = 0;

			// Skip version if present
			if (rdParts.get(idx).isContextSpecific() && rdParts.get(idx).getContextTag() == 0) {
				idx++;
			}
			// Skip responderID and producedAt
			idx += 2;

			// responses (SEQUENCE OF SingleResponse)
			if (idx < rdParts.size()) {
				List<DerParser.DerValue> responses = rdParts.get(idx).getSequence();
				if (!responses.isEmpty()) {
					List<DerParser.DerValue> srParts = responses.get(0).getSequence();
					// Look for singleExtensions [1]
					for (DerParser.DerValue part : srParts) {
						if (part.isContextSpecific() && part.getContextTag() == 1) {
							// Extensions sequence
							List<DerParser.DerValue> extensions = part.getTaggedSequence();
							for (DerParser.DerValue ext : extensions) {
								List<DerParser.DerValue> extParts = ext.getSequence();
								if (extParts.size() >= 2) {
									String oid = extParts.get(0).getObjectIdentifier();
									// OID 1.3.6.1.4.1.11129.2.4.5 = SCT in OCSP
									if ("1.3.6.1.4.1.11129.2.4.5".equals(oid)) {
										return extParts.get(extParts.size() - 1).getOctetString();
									}
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to extract SCT extension from OCSP response", e);
		}
		return null;
	}

	// --- Utility methods ---

	private static String formatDate(Date date) {
		return ISO_FMT.format(date.toInstant().atOffset(ZoneOffset.UTC));
	}
}
