package com.mps.deepviolet.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * X.509 extension parsing utilities to replace Bouncy Castle dependencies.
 * Extracts URLs and other data from certificate extensions.
 *
 * @author Milton Smith
 */
public class X509Extensions {

    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.util.X509Extensions");

    // OIDs for common extensions
    public static final String OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
    public static final String OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    public static final String OID_SUBJECT_ALT_NAME = "2.5.29.17";
    public static final String OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";
    public static final String OID_MUST_STAPLE = "1.3.6.1.5.5.7.1.24";

    // Access method OIDs within AIA
    public static final String OID_OCSP = "1.3.6.1.5.5.7.48.1";
    public static final String OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2";

    // GeneralName tag numbers
    public static final int GN_OTHER_NAME = 0;
    public static final int GN_RFC822_NAME = 1;
    public static final int GN_DNS_NAME = 2;
    public static final int GN_X400_ADDRESS = 3;
    public static final int GN_DIRECTORY_NAME = 4;
    public static final int GN_EDI_PARTY_NAME = 5;
    public static final int GN_URI = 6;
    public static final int GN_IP_ADDRESS = 7;
    public static final int GN_REGISTERED_ID = 8;

    private X509Extensions() {}

    /**
     * Extract the OCSP responder URL from Authority Information Access extension.
     *
     * @param cert The certificate to examine
     * @return The OCSP responder URL, or null if not found
     */
    public static String getOcspUrl(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue(OID_AUTHORITY_INFO_ACCESS);
            if (extValue == null) {
                return null;
            }

            // Unwrap OCTET STRING wrapper
            DerParser.DerValue outer = DerParser.parse(extValue);
            byte[] aiaBytes = outer.getOctetString();

            // Parse the AIA sequence
            DerParser.DerValue aiaSeq = DerParser.parse(aiaBytes);
            List<DerParser.DerValue> accessDescriptions = aiaSeq.getSequence();

            for (DerParser.DerValue ad : accessDescriptions) {
                List<DerParser.DerValue> parts = ad.getSequence();
                if (parts.size() >= 2) {
                    String oid = parts.get(0).getObjectIdentifier();
                    if (OID_OCSP.equals(oid)) {
                        // AccessLocation is a GeneralName
                        DerParser.DerValue gnValue = parts.get(1);
                        if (gnValue.isContextSpecific() && gnValue.getContextTag() == GN_URI) {
                            return gnValue.getStringValue();
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to extract OCSP URL", e);
        }
        return null;
    }

    /**
     * Extract the CA Issuers URL from Authority Information Access extension.
     *
     * @param cert The certificate to examine
     * @return The CA Issuers URL, or null if not found
     */
    public static String getCaIssuersUrl(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue(OID_AUTHORITY_INFO_ACCESS);
            if (extValue == null) {
                return null;
            }

            // Unwrap OCTET STRING wrapper
            DerParser.DerValue outer = DerParser.parse(extValue);
            byte[] aiaBytes = outer.getOctetString();

            // Parse the AIA sequence
            DerParser.DerValue aiaSeq = DerParser.parse(aiaBytes);
            List<DerParser.DerValue> accessDescriptions = aiaSeq.getSequence();

            for (DerParser.DerValue ad : accessDescriptions) {
                List<DerParser.DerValue> parts = ad.getSequence();
                if (parts.size() >= 2) {
                    String oid = parts.get(0).getObjectIdentifier();
                    if (OID_CA_ISSUERS.equals(oid)) {
                        // AccessLocation is a GeneralName
                        DerParser.DerValue gnValue = parts.get(1);
                        if (gnValue.isContextSpecific() && gnValue.getContextTag() == GN_URI) {
                            return gnValue.getStringValue();
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to extract CA Issuers URL", e);
        }
        return null;
    }

    /**
     * Extract CRL distribution point URLs from the certificate.
     *
     * @param cert The certificate to examine
     * @return List of CRL URLs, may be empty
     */
    public static List<String> getCrlUrls(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        try {
            byte[] extValue = cert.getExtensionValue(OID_CRL_DISTRIBUTION_POINTS);
            if (extValue == null) {
                return urls;
            }

            // Unwrap OCTET STRING wrapper
            DerParser.DerValue outer = DerParser.parse(extValue);
            byte[] crlDpBytes = outer.getOctetString();

            // Parse the CRLDistributionPoints sequence
            DerParser.DerValue dpSeq = DerParser.parse(crlDpBytes);
            List<DerParser.DerValue> distPoints = dpSeq.getSequence();

            for (DerParser.DerValue dp : distPoints) {
                extractUrlsFromDistributionPoint(dp, urls);
            }
        } catch (Exception e) {
            logger.debug("Failed to extract CRL URLs", e);
        }
        return urls;
    }

    /**
     * Extract URLs from a single distribution point.
     */
    private static void extractUrlsFromDistributionPoint(DerParser.DerValue dp, List<String> urls) throws IOException {
        List<DerParser.DerValue> dpParts = dp.getSequence();
        for (DerParser.DerValue part : dpParts) {
            if (part.isContextSpecific() && part.getContextTag() == 0) {
                // DistributionPointName
                List<DerParser.DerValue> dpNameParts = part.getTaggedSequence();
                for (DerParser.DerValue dpNamePart : dpNameParts) {
                    if (dpNamePart.isContextSpecific() && dpNamePart.getContextTag() == 0) {
                        // fullName - sequence of GeneralNames
                        extractGeneralNameUrls(dpNamePart, urls);
                    }
                }
            }
        }
    }

    /**
     * Extract URIs from GeneralNames.
     */
    private static void extractGeneralNameUrls(DerParser.DerValue gnContainer, List<String> urls) throws IOException {
        // May be a sequence or single value
        if (gnContainer.isConstructed()) {
            List<DerParser.DerValue> gns = gnContainer.getTaggedSequence();
            for (DerParser.DerValue gn : gns) {
                if (gn.isContextSpecific() && gn.getContextTag() == GN_URI) {
                    String url = gn.getStringValue();
                    if (url != null && url.startsWith("http")) {
                        urls.add(url);
                    }
                }
            }
        } else if (gnContainer.isContextSpecific() && gnContainer.getContextTag() == GN_URI) {
            String url = gnContainer.getStringValue();
            if (url != null && url.startsWith("http")) {
                urls.add(url);
            }
        }
    }

    /**
     * Extract the first CRL URL from the certificate.
     *
     * @param cert The certificate to examine
     * @return The first CRL URL, or null if not found
     */
    public static String getCrlUrl(X509Certificate cert) {
        List<String> urls = getCrlUrls(cert);
        return urls.isEmpty() ? null : urls.get(0);
    }

    /**
     * Extract Subject Alternative Names from the certificate.
     *
     * @param cert The certificate to examine
     * @return List of SANs as strings (DNS names, IPs, emails, URIs)
     */
    public static List<String> getSubjectAlternativeNames(X509Certificate cert) {
        List<String> sans = new ArrayList<>();
        try {
            byte[] extValue = cert.getExtensionValue(OID_SUBJECT_ALT_NAME);
            if (extValue == null) {
                return sans;
            }

            // Unwrap OCTET STRING wrapper
            DerParser.DerValue outer = DerParser.parse(extValue);
            byte[] sanBytes = outer.getOctetString();

            // Parse the GeneralNames sequence
            DerParser.DerValue sanSeq = DerParser.parse(sanBytes);
            List<DerParser.DerValue> generalNames = sanSeq.getSequence();

            for (DerParser.DerValue gn : generalNames) {
                if (gn.isContextSpecific()) {
                    int tag = gn.getContextTag();
                    switch (tag) {
                        case GN_DNS_NAME:
                        case GN_RFC822_NAME:
                        case GN_URI:
                            sans.add(gn.getStringValue());
                            break;
                        case GN_IP_ADDRESS:
                            sans.add(formatIpAddress(gn.getValue()));
                            break;
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to extract SANs", e);
        }
        return sans;
    }

    /**
     * Format an IP address from its byte representation.
     */
    private static String formatIpAddress(byte[] data) {
        if (data.length == 4) {
            // IPv4
            return String.format("%d.%d.%d.%d",
                data[0] & 0xFF, data[1] & 0xFF, data[2] & 0xFF, data[3] & 0xFF);
        } else if (data.length == 16) {
            // IPv6
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i += 2) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02x%02x", data[i] & 0xFF, data[i + 1] & 0xFF));
            }
            return sb.toString();
        }
        return DerParser.toHex(data);
    }

    /**
     * Extract Signed Certificate Timestamps (SCTs) from the certificate extension.
     *
     * @param cert The certificate to examine
     * @return List of SCT details as strings
     */
    public static List<SignedCertificateTimestamp> getScts(X509Certificate cert) {
        List<SignedCertificateTimestamp> scts = new ArrayList<>();
        try {
            byte[] extValue = cert.getExtensionValue(OID_SCT_LIST);
            if (extValue == null) {
                return scts;
            }

            // Unwrap OCTET STRING wrapper(s)
            DerParser.DerValue outer = DerParser.parse(extValue);
            byte[] innerBytes = outer.getOctetString();

            // May be double-wrapped
            DerParser.DerValue inner = DerParser.parse(innerBytes);
            byte[] sctListBytes = inner.getOctetString();

            // Parse TLS-encoded SCT list
            scts = parseSctList(sctListBytes);

        } catch (Exception e) {
            logger.debug("Failed to extract SCTs", e);
        }
        return scts;
    }

    /**
     * Parse a TLS-encoded SCT list.
     */
    public static List<SignedCertificateTimestamp> parseSctList(byte[] data) {
        List<SignedCertificateTimestamp> scts = new ArrayList<>();
        if (data == null || data.length < 2) {
            return scts;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        int totalLen = buf.getShort() & 0xFFFF;
        int end = buf.position() + totalLen;

        while (buf.position() < end && buf.remaining() >= 2) {
            int sctLen = buf.getShort() & 0xFFFF;
            if (sctLen <= 0 || buf.remaining() < sctLen) {
                break;
            }

            int sctStart = buf.position();
            try {
                SignedCertificateTimestamp sct = new SignedCertificateTimestamp();

                // Version: 1 byte
                sct.version = buf.get() & 0xFF;

                // LogID: 32 bytes
                sct.logId = new byte[32];
                buf.get(sct.logId);

                // Timestamp: 8 bytes (ms since epoch)
                sct.timestamp = buf.getLong();

                // Extensions length: 2 bytes
                int extLen = buf.getShort() & 0xFFFF;
                sct.extensions = new byte[extLen];
                if (extLen > 0) {
                    buf.get(sct.extensions);
                }

                // Hash algorithm: 1 byte
                sct.hashAlgorithm = buf.get() & 0xFF;

                // Signature algorithm: 1 byte
                sct.signatureAlgorithm = buf.get() & 0xFF;

                // Signature length: 2 bytes
                int sigLen = buf.getShort() & 0xFFFF;
                sct.signature = new byte[sigLen];
                if (sigLen > 0) {
                    buf.get(sct.signature);
                }

                scts.add(sct);
            } catch (Exception e) {
                logger.debug("Failed to parse SCT", e);
            }

            // Move to next SCT
            buf.position(sctStart + sctLen);
        }

        return scts;
    }

    /**
     * Check if the certificate has the Must-Staple extension.
     *
     * @param cert The certificate to examine
     * @return true if Must-Staple is present
     */
    public static boolean hasMustStaple(X509Certificate cert) {
        return cert.getExtensionValue(OID_MUST_STAPLE) != null;
    }

    /**
     * Represents a Signed Certificate Timestamp.
     */
    public static class SignedCertificateTimestamp {
        public int version;
        public byte[] logId;
        public long timestamp;
        public byte[] extensions;
        public int hashAlgorithm;
        public int signatureAlgorithm;
        public byte[] signature;

        /**
         * Get the timestamp as an Instant.
         */
        public Instant getTimestampInstant() {
            return Instant.ofEpochMilli(timestamp);
        }

        /**
         * Get the timestamp as an ISO-8601 string.
         */
        public String getTimestampString() {
            return DateTimeFormatter.ISO_INSTANT.format(getTimestampInstant());
        }

        /**
         * Get the first 8 bytes of the log ID as a hex string (for compact display).
         */
        public String getLogIdPrefix() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(8, logId.length); i++) {
                sb.append(String.format("%02x", logId[i] & 0xFF));
            }
            return sb.toString();
        }

        /**
         * Get the full log ID as a hex string (for lookup in CT log lists).
         */
        public String getLogIdHex() {
            StringBuilder sb = new StringBuilder();
            for (byte b : logId) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        }

        /**
         * Get the full log ID as a Base64 string (standard CT log format).
         */
        public String getLogIdBase64() {
            return java.util.Base64.getEncoder().encodeToString(logId);
        }

        @Override
        public String toString() {
            return String.format("Version=%d LogID=%s Timestamp=%s",
                version, getLogIdBase64(), getTimestampString());
        }
    }
}
