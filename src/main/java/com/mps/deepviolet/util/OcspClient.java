package com.mps.deepviolet.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OCSP client implementation using JDK classes, replacing Bouncy Castle.
 * Builds OCSP requests, sends them to responders, and parses responses.
 *
 * @author Milton Smith
 */
public class OcspClient {

    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.util.OcspClient");

    // Default timeout for network operations
    private static final int DEFAULT_TIMEOUT_MS = 8000;

    /** OCSP response status: successful. */
    public static final int OCSP_SUCCESSFUL = 0;
    /** OCSP response status: malformed request. */
    public static final int OCSP_MALFORMED_REQUEST = 1;
    /** OCSP response status: internal error. */
    public static final int OCSP_INTERNAL_ERROR = 2;
    /** OCSP response status: try later. */
    public static final int OCSP_TRY_LATER = 3;
    /** OCSP response status: signature required. */
    public static final int OCSP_SIG_REQUIRED = 5;
    /** OCSP response status: unauthorized. */
    public static final int OCSP_UNAUTHORIZED = 6;

    /** Certificate status: good (not revoked). */
    public static final int CERT_STATUS_GOOD = 0;
    /** Certificate status: revoked. */
    public static final int CERT_STATUS_REVOKED = 1;
    /** Certificate status: unknown. */
    public static final int CERT_STATUS_UNKNOWN = 2;

    // OIDs
    private static final String OID_SHA1 = "1.3.14.3.2.26";
    private static final String OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
    private static final String OID_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

    private int timeoutMs = DEFAULT_TIMEOUT_MS;

    /**
     * Create a new OCSP client with default settings.
     */
    public OcspClient() {}

    /**
     * Set the network timeout in milliseconds.
     * @param timeoutMs timeout in milliseconds
     */
    public void setTimeoutMs(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    /**
     * Check the revocation status of a certificate using OCSP.
     *
     * @param cert The certificate to check
     * @param issuer The issuer certificate
     * @return The OCSP response, or null if the check failed
     */
    public OcspResponse check(X509Certificate cert, X509Certificate issuer) {
        String ocspUrl = X509Extensions.getOcspUrl(cert);
        if (ocspUrl == null) {
            OcspResponse response = new OcspResponse();
            response.status = Status.ERROR;
            response.errorMessage = "No OCSP responder URL in certificate";
            return response;
        }
        return check(cert, issuer, ocspUrl);
    }

    /**
     * Check the revocation status of a certificate using a specific OCSP URL.
     *
     * @param cert The certificate to check
     * @param issuer The issuer certificate
     * @param ocspUrl The OCSP responder URL
     * @return The OCSP response
     */
    public OcspResponse check(X509Certificate cert, X509Certificate issuer, String ocspUrl) {
        OcspResponse response = new OcspResponse();
        response.responderUrl = ocspUrl;

        try {
            // Build the OCSP request
            byte[] requestBytes = buildOcspRequest(cert, issuer);

            // Send the request
            long startTime = System.nanoTime();
            byte[] responseBytes = sendOcspRequest(ocspUrl, requestBytes);
            response.responseTimeMs = (System.nanoTime() - startTime) / 1_000_000;

            // Parse the response (pass issuer for signature verification)
            parseOcspResponse(responseBytes, response, issuer);

        } catch (Exception e) {
            logger.error("OCSP check failed", e);
            response.status = Status.ERROR;
            response.errorMessage = e.getMessage();
        }

        return response;
    }

    /**
     * Build an OCSP request for the given certificate.
     */
    private byte[] buildOcspRequest(X509Certificate cert, X509Certificate issuer) throws Exception {
        ByteArrayOutputStream request = new ByteArrayOutputStream();

        // Build CertID
        byte[] certId = buildCertId(cert, issuer);

        // Build Request (contains CertID)
        byte[] singleRequest = wrapSequence(certId);

        // Build RequestList (SEQUENCE OF Request)
        byte[] requestList = wrapSequence(singleRequest);

        // Build TBSRequest (contains RequestList)
        byte[] tbsRequest = wrapSequence(requestList);

        // Build OCSPRequest (contains TBSRequest)
        byte[] ocspRequest = wrapSequence(tbsRequest);

        return ocspRequest;
    }

    /**
     * Build the CertID structure for an OCSP request.
     * CertID ::= SEQUENCE {
     *   hashAlgorithm  AlgorithmIdentifier,
     *   issuerNameHash OCTET STRING,
     *   issuerKeyHash  OCTET STRING,
     *   serialNumber   CertificateSerialNumber
     * }
     */
    private byte[] buildCertId(X509Certificate cert, X509Certificate issuer) throws Exception {
        ByteArrayOutputStream certId = new ByteArrayOutputStream();

        // Hash algorithm (SHA-1)
        byte[] hashAlgId = buildHashAlgorithmIdentifier();
        certId.write(hashAlgId);

        // Issuer name hash
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] issuerNameHash = sha1.digest(issuer.getSubjectX500Principal().getEncoded());
        certId.write(wrapOctetString(issuerNameHash));

        // Issuer key hash (hash of issuer's public key without the algorithm identifier)
        sha1.reset();
        byte[] issuerPublicKeyInfo = issuer.getPublicKey().getEncoded();
        byte[] issuerKeyBits = extractPublicKeyBits(issuerPublicKeyInfo);
        byte[] issuerKeyHash = sha1.digest(issuerKeyBits);
        certId.write(wrapOctetString(issuerKeyHash));

        // Serial number
        certId.write(wrapInteger(cert.getSerialNumber()));

        return wrapSequence(certId.toByteArray());
    }

    /**
     * Build AlgorithmIdentifier for SHA-1.
     */
    private byte[] buildHashAlgorithmIdentifier() throws IOException {
        ByteArrayOutputStream algId = new ByteArrayOutputStream();

        // OID for SHA-1
        byte[] sha1Oid = DerParser.encodeOid(OID_SHA1);
        algId.write(0x06); // OBJECT IDENTIFIER tag
        algId.write(sha1Oid.length);
        algId.write(sha1Oid);

        // NULL parameters
        algId.write(0x05); // NULL tag
        algId.write(0x00); // length 0

        return wrapSequence(algId.toByteArray());
    }

    /**
     * Extract the public key bit string from SubjectPublicKeyInfo.
     */
    private byte[] extractPublicKeyBits(byte[] spki) throws IOException {
        // Parse SubjectPublicKeyInfo
        DerParser.DerValue spkiSeq = DerParser.parse(spki);
        List<DerParser.DerValue> parts = spkiSeq.getSequence();
        if (parts.size() >= 2) {
            // Second element is the BIT STRING containing the public key
            return parts.get(1).getBitString();
        }
        throw new IOException("Invalid SubjectPublicKeyInfo structure");
    }

    /**
     * Send an OCSP request to the responder.
     */
    private byte[] sendOcspRequest(String ocspUrl, byte[] requestBytes) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) URI.create(ocspUrl).toURL().openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestProperty("Content-Type", "application/ocsp-request");
            conn.setRequestProperty("Accept", "application/ocsp-response");
            conn.setFixedLengthStreamingMode(requestBytes.length);

            try (OutputStream out = conn.getOutputStream()) {
                out.write(requestBytes);
            }

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("OCSP responder returned HTTP " + responseCode);
            }

            try (InputStream in = conn.getInputStream()) {
                return in.readAllBytes();
            }
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Parse an OCSP response.
     *
     * @param responseBytes Raw OCSP response bytes
     * @param response Response object to populate
     * @param issuer Issuer certificate for signature verification
     */
    private void parseOcspResponse(byte[] responseBytes, OcspResponse response, X509Certificate issuer) throws Exception {
        // OCSPResponse ::= SEQUENCE {
        //   responseStatus OCSPResponseStatus,
        //   responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
        // }
        DerParser.DerValue ocspResp = DerParser.parse(responseBytes);
        List<DerParser.DerValue> respParts = ocspResp.getSequence();

        if (respParts.isEmpty()) {
            throw new IOException("Empty OCSP response");
        }

        // Response status
        int responseStatus = respParts.get(0).getIntValue();
        if (responseStatus != OCSP_SUCCESSFUL) {
            response.status = Status.ERROR;
            response.errorMessage = "OCSP responder " + ocspResponseStatusDescription(responseStatus);
            return;
        }

        if (respParts.size() < 2) {
            response.status = Status.ERROR;
            response.errorMessage = "OCSP response has no responseBytes";
            return;
        }

        // responseBytes [0]
        DerParser.DerValue responseBytesTagged = respParts.get(1);
        DerParser.DerValue responseBytesSeq = responseBytesTagged.getTaggedObject();
        List<DerParser.DerValue> rbParts = responseBytesSeq.getSequence();

        if (rbParts.size() < 2) {
            throw new IOException("Invalid ResponseBytes structure");
        }

        // Check response type (should be basicOCSPResponse)
        String responseType = rbParts.get(0).getObjectIdentifier();
        if (!OID_OCSP_BASIC.equals(responseType)) {
            response.status = Status.ERROR;
            response.errorMessage = "Unsupported OCSP response type: " + responseType;
            return;
        }

        // Parse BasicOCSPResponse
        byte[] basicRespBytes = rbParts.get(1).getOctetString();
        parseBasicOcspResponse(basicRespBytes, response, issuer);
    }

    /**
     * Parse a BasicOCSPResponse and verify its signature.
     *
     * @param basicRespBytes Raw BasicOCSPResponse bytes
     * @param response Response object to populate
     * @param issuer Issuer certificate for signature verification
     */
    private void parseBasicOcspResponse(byte[] basicRespBytes, OcspResponse response, X509Certificate issuer) throws Exception {
        // BasicOCSPResponse ::= SEQUENCE {
        //   tbsResponseData   ResponseData,
        //   signatureAlgorithm AlgorithmIdentifier,
        //   signature         BIT STRING,
        //   certs         [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
        // }
        DerParser.DerValue basicResp = DerParser.parse(basicRespBytes);
        List<DerParser.DerValue> basicParts = basicResp.getSequence();

        if (basicParts.size() < 3) {
            throw new IOException("Invalid BasicOCSPResponse structure");
        }

        // Parse ResponseData (for status, timestamps, etc.)
        parseResponseData(basicParts.get(0), response);

        // Extract signature algorithm
        List<DerParser.DerValue> algParts = basicParts.get(1).getSequence();
        String sigAlgOid = algParts.get(0).getObjectIdentifier();
        String sigAlgName = oidToSignatureAlgorithm(sigAlgOid);

        // Extract signature bits
        byte[] signatureBytes = basicParts.get(2).getBitString();

        // Get the TBS data bytes for verification (full DER encoding of ResponseData)
        byte[] tbsBytes = reEncodeToDer(basicParts.get(0));

        // Try to find the responder certificate
        X509Certificate responderCert = null;

        // Check for embedded certs [0] EXPLICIT SEQUENCE OF Certificate
        if (basicParts.size() > 3 && basicParts.get(3).isContextSpecific()) {
            try {
                // The [0] tag wraps a SEQUENCE OF Certificate
                List<DerParser.DerValue> seqWrapper = basicParts.get(3).getTaggedSequence();
                if (!seqWrapper.isEmpty()) {
                    // Get the SEQUENCE OF certificates
                    List<DerParser.DerValue> certList = seqWrapper.get(0).getSequence();
                    if (!certList.isEmpty()) {
                        // Re-encode the first certificate to DER for parsing
                        byte[] certBytes = reEncodeToDer(certList.get(0));
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        responderCert = (X509Certificate) cf.generateCertificate(
                                new ByteArrayInputStream(certBytes));
                        logger.debug("Parsed embedded OCSP responder cert: " + responderCert.getSubjectX500Principal());
                    }
                }
            } catch (Exception e) {
                logger.debug("Could not parse embedded responder certificate: " + e.getMessage());
            }
        }

        // Verify signature
        response.signatureValid = verifyOcspSignature(tbsBytes, signatureBytes, sigAlgName,
                responderCert, issuer);
    }

    /**
     * Map an OCSP response status code (RFC 6960) to a short description.
     */
    private static String ocspResponseStatusDescription(int code) {
        switch (code) {
            case OCSP_MALFORMED_REQUEST: return "rejected malformed request";
            case OCSP_INTERNAL_ERROR:    return "internal error";
            case OCSP_TRY_LATER:         return "temporarily unavailable";
            case OCSP_SIG_REQUIRED:      return "requires signed request";
            case OCSP_UNAUTHORIZED:      return "rejected unauthorized request";
            default:                     return "returned unknown status (" + code + ")";
        }
    }

    /**
     * Re-encode a DerValue to full DER format (tag + length + value).
     */
    private byte[] reEncodeToDer(DerParser.DerValue dv) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int tag = dv.getTag();
        byte[] value = dv.getValue();

        baos.write(tag);
        writeDerLength(baos, value.length);
        baos.write(value);

        return baos.toByteArray();
    }

    /**
     * Write DER length encoding.
     */
    private void writeDerLength(ByteArrayOutputStream baos, int length) {
        if (length < 128) {
            baos.write(length);
        } else if (length < 256) {
            baos.write(0x81);
            baos.write(length);
        } else if (length < 65536) {
            baos.write(0x82);
            baos.write((length >> 8) & 0xFF);
            baos.write(length & 0xFF);
        } else {
            baos.write(0x83);
            baos.write((length >> 16) & 0xFF);
            baos.write((length >> 8) & 0xFF);
            baos.write(length & 0xFF);
        }
    }

    /**
     * Verify OCSP response signature.
     *
     * @param tbsData The to-be-signed ResponseData bytes
     * @param signature The signature bytes
     * @param algorithm The signature algorithm name
     * @param responderCert The embedded responder certificate (may be null)
     * @param issuerCert The certificate issuer
     * @return true if signature is valid, false otherwise
     */
    private boolean verifyOcspSignature(byte[] tbsData, byte[] signature, String algorithm,
            X509Certificate responderCert, X509Certificate issuerCert) {
        try {
            logger.debug("OCSP sig verify: alg=" + algorithm +
                    ", tbsLen=" + tbsData.length + ", sigLen=" + signature.length);

            // Try responder cert first if available
            if (responderCert != null) {
                logger.debug("Trying responder cert: " + responderCert.getSubjectX500Principal());
                if (verifyWithCert(tbsData, signature, algorithm, responderCert)) {
                    logger.debug("OCSP signature verified with responder cert");
                    return true;
                }
                logger.debug("Responder cert verification failed");
            } else {
                logger.debug("No responder cert available");
            }

            // Try issuer cert (CA may sign OCSP responses directly)
            if (issuerCert != null) {
                logger.debug("Trying issuer cert: " + issuerCert.getSubjectX500Principal());
                if (verifyWithCert(tbsData, signature, algorithm, issuerCert)) {
                    logger.debug("OCSP signature verified with issuer cert");
                    return true;
                }
                logger.debug("Issuer cert verification failed");
            }

            logger.debug("OCSP signature verification failed with all available certificates");
            return false;

        } catch (Exception e) {
            logger.debug("OCSP signature verification error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Attempt to verify signature with a specific certificate.
     */
    private boolean verifyWithCert(byte[] tbsData, byte[] signature, String algorithm,
            X509Certificate cert) {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(cert.getPublicKey());
            sig.update(tbsData);
            return sig.verify(signature);
        } catch (Exception e) {
            logger.trace("Signature verification with cert failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Convert signature algorithm OID to Java algorithm name.
     */
    private String oidToSignatureAlgorithm(String oid) {
        switch (oid) {
            case "1.2.840.113549.1.1.5":
                return "SHA1withRSA";
            case "1.2.840.113549.1.1.11":
                return "SHA256withRSA";
            case "1.2.840.113549.1.1.12":
                return "SHA384withRSA";
            case "1.2.840.113549.1.1.13":
                return "SHA512withRSA";
            case "1.2.840.10045.4.1":
                return "SHA1withECDSA";
            case "1.2.840.10045.4.3.2":
                return "SHA256withECDSA";
            case "1.2.840.10045.4.3.3":
                return "SHA384withECDSA";
            case "1.2.840.10045.4.3.4":
                return "SHA512withECDSA";
            default:
                logger.warn("Unknown signature algorithm OID: " + oid);
                return "SHA256withRSA"; // Default fallback
        }
    }

    /**
     * Parse ResponseData to extract certificate status.
     */
    private void parseResponseData(DerParser.DerValue responseData, OcspResponse response) throws Exception {
        // ResponseData ::= SEQUENCE {
        //   version          [0] EXPLICIT Version DEFAULT v1,
        //   responderID      ResponderID,
        //   producedAt       GeneralizedTime,
        //   responses        SEQUENCE OF SingleResponse,
        //   responseExtensions [1] EXPLICIT Extensions OPTIONAL
        // }
        List<DerParser.DerValue> rdParts = responseData.getSequence();

        int idx = 0;

        // Skip version if present (tagged [0])
        if (rdParts.get(idx).isContextSpecific() && rdParts.get(idx).getContextTag() == 0) {
            idx++;
        }

        // Skip responderID
        idx++;

        // Skip producedAt
        idx++;

        // responses (SEQUENCE OF SingleResponse)
        if (idx < rdParts.size()) {
            List<DerParser.DerValue> responses = rdParts.get(idx).getSequence();
            if (!responses.isEmpty()) {
                parseSingleResponse(responses.get(0), response);
            }
        }
    }

    /**
     * Parse a SingleResponse to extract certificate status.
     */
    private void parseSingleResponse(DerParser.DerValue singleResp, OcspResponse response) throws Exception {
        // SingleResponse ::= SEQUENCE {
        //   certID       CertID,
        //   certStatus   CertStatus,
        //   thisUpdate   GeneralizedTime,
        //   nextUpdate   [0] EXPLICIT GeneralizedTime OPTIONAL,
        //   singleExtensions [1] EXPLICIT Extensions OPTIONAL
        // }
        List<DerParser.DerValue> srParts = singleResp.getSequence();

        if (srParts.size() < 3) {
            throw new IOException("Invalid SingleResponse structure");
        }

        // certStatus (index 1)
        DerParser.DerValue certStatus = srParts.get(1);

        if (certStatus.isContextSpecific()) {
            int tag = certStatus.getContextTag();
            switch (tag) {
                case 0: // good [0] IMPLICIT NULL
                    response.status = Status.GOOD;
                    break;
                case 1: // revoked [1] IMPLICIT RevokedInfo
                    response.status = Status.REVOKED;
                    parseRevokedInfo(certStatus, response);
                    break;
                case 2: // unknown [2] IMPLICIT UnknownInfo
                    response.status = Status.UNKNOWN;
                    break;
                default:
                    response.status = Status.UNKNOWN;
            }
        } else {
            // NULL means good
            response.status = Status.GOOD;
        }

        // thisUpdate (index 2)
        if (srParts.size() > 2) {
            response.thisUpdate = parseGeneralizedTime(srParts.get(2));
        }

        // nextUpdate (tagged [0])
        for (int i = 3; i < srParts.size(); i++) {
            DerParser.DerValue part = srParts.get(i);
            if (part.isContextSpecific() && part.getContextTag() == 0) {
                DerParser.DerValue nextUpdateVal = part.getTaggedObject();
                response.nextUpdate = parseGeneralizedTime(nextUpdateVal);
            }
        }
    }

    /**
     * Parse RevokedInfo to extract revocation time and reason.
     */
    private void parseRevokedInfo(DerParser.DerValue revokedInfo, OcspResponse response) {
        try {
            // RevokedInfo ::= SEQUENCE {
            //   revocationTime GeneralizedTime,
            //   revocationReason [0] EXPLICIT CRLReason OPTIONAL
            // }
            List<DerParser.DerValue> riParts = revokedInfo.getTaggedSequence();
            if (!riParts.isEmpty()) {
                response.revocationTime = parseGeneralizedTime(riParts.get(0));

                // Look for revocation reason
                for (int i = 1; i < riParts.size(); i++) {
                    DerParser.DerValue part = riParts.get(i);
                    if (part.isContextSpecific() && part.getContextTag() == 0) {
                        DerParser.DerValue reasonVal = part.getTaggedObject();
                        int reason = reasonVal.getIntValue();
                        response.revocationReason = getCrlReasonString(reason);
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to parse RevokedInfo", e);
        }
    }

    /**
     * Parse a GeneralizedTime value.
     */
    private Date parseGeneralizedTime(DerParser.DerValue timeVal) {
        try {
            String timeStr = timeVal.getString();
            // Format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.sssZ
            Instant instant;
            if (timeStr.contains(".")) {
                instant = DateTimeFormatter.ofPattern("yyyyMMddHHmmss.SSSX")
                    .parse(timeStr, Instant::from);
            } else if (timeStr.endsWith("Z")) {
                instant = DateTimeFormatter.ofPattern("yyyyMMddHHmmssX")
                    .parse(timeStr, Instant::from);
            } else {
                // No timezone - assume UTC
                instant = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")
                    .withZone(ZoneOffset.UTC)
                    .parse(timeStr, Instant::from);
            }
            return Date.from(instant);
        } catch (Exception e) {
            logger.debug("Failed to parse GeneralizedTime", e);
            return null;
        }
    }

    /**
     * Get a human-readable CRL reason string.
     */
    private String getCrlReasonString(int reason) {
        switch (reason) {
            case 0: return "unspecified";
            case 1: return "keyCompromise";
            case 2: return "cACompromise";
            case 3: return "affiliationChanged";
            case 4: return "superseded";
            case 5: return "cessationOfOperation";
            case 6: return "certificateHold";
            case 8: return "removeFromCRL";
            case 9: return "privilegeWithdrawn";
            case 10: return "aACompromise";
            default: return "unknown(" + reason + ")";
        }
    }

    // --- DER encoding helpers ---

    private byte[] wrapSequence(byte[] content) {
        return wrap(0x30, content);
    }

    private byte[] wrapOctetString(byte[] content) {
        return wrap(0x04, content);
    }

    private byte[] wrapInteger(BigInteger value) {
        byte[] intBytes = value.toByteArray();
        return wrap(0x02, intBytes);
    }

    private byte[] wrap(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    private void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length & 0xFF);
        } else {
            out.write(0x83);
            out.write(length >> 16);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    // --- Response classes ---

    /**
     * Certificate status from OCSP check.
     */
    public enum Status {
        /** Certificate is not revoked. */
        GOOD,
        /** Certificate has been revoked. */
        REVOKED,
        /** Revocation status is unknown. */
        UNKNOWN,
        /** An error occurred during the check. */
        ERROR,
        /** Revocation has not been checked. */
        NOT_CHECKED
    }

    /**
     * OCSP response details.
     */
    public static class OcspResponse {
        /** Creates an OcspResponse with default NOT_CHECKED status. */
        public OcspResponse() {}
        /** OCSP certificate status. */
        public Status status = Status.NOT_CHECKED;
        /** URL of the OCSP responder. */
        public String responderUrl;
        /** Response time in milliseconds. */
        public long responseTimeMs;
        /** When the status was last confirmed. */
        public Date thisUpdate;
        /** When the status should next be checked. */
        public Date nextUpdate;
        /** When the certificate was revoked, if applicable. */
        public Date revocationTime;
        /** Revocation reason, if applicable. */
        public String revocationReason;
        /** Whether the OCSP response signature is valid. */
        public Boolean signatureValid;
        /** Error message, if an error occurred. */
        public String errorMessage;

        /**
         * Format thisUpdate as ISO-8601 string.
         * @return ISO-8601 formatted date string, or null
         */
        public String getThisUpdateString() {
            if (thisUpdate == null) return null;
            return DateTimeFormatter.ISO_INSTANT.format(thisUpdate.toInstant());
        }

        /**
         * Format nextUpdate as ISO-8601 string.
         * @return ISO-8601 formatted date string, or null
         */
        public String getNextUpdateString() {
            if (nextUpdate == null) return null;
            return DateTimeFormatter.ISO_INSTANT.format(nextUpdate.toInstant());
        }

        /**
         * Format revocationTime as ISO-8601 string.
         * @return ISO-8601 formatted date string, or null
         */
        public String getRevocationTimeString() {
            if (revocationTime == null) return null;
            return DateTimeFormatter.ISO_INSTANT.format(revocationTime.toInstant());
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("OcspResponse[status=").append(status);
            if (responderUrl != null) {
                sb.append(", url=").append(responderUrl);
            }
            sb.append(", responseTime=").append(responseTimeMs).append("ms");
            if (thisUpdate != null) {
                sb.append(", thisUpdate=").append(getThisUpdateString());
            }
            if (nextUpdate != null) {
                sb.append(", nextUpdate=").append(getNextUpdateString());
            }
            if (status == Status.REVOKED && revocationTime != null) {
                sb.append(", revocationTime=").append(getRevocationTimeString());
                if (revocationReason != null) {
                    sb.append(", reason=").append(revocationReason);
                }
            }
            if (errorMessage != null) {
                sb.append(", error=").append(errorMessage);
            }
            sb.append("]");
            return sb.toString();
        }
    }
}
