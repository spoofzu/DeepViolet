package com.mps.deepviolet.api.tls;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parses TLS Certificate message and extracts certificate chain with embedded SCTs.
 *
 * Certificate message structure (RFC 5246 / RFC 8446):
 * TLS 1.2:
 * - certificates_length: 3 bytes
 * - for each certificate:
 *   - certificate_length: 3 bytes
 *   - certificate: DER-encoded X.509
 *
 * TLS 1.3:
 * - certificate_request_context_length: 1 byte
 * - certificate_request_context: variable
 * - certificate_list_length: 3 bytes
 * - for each certificate:
 *   - cert_data_length: 3 bytes
 *   - cert_data: DER-encoded X.509
 *   - extensions_length: 2 bytes
 *   - extensions: may contain SCT extension
 */
public class CertificateMessage {

    // OID for SCT extension in X.509 certificates
    public static final String SCT_X509_OID = "1.3.6.1.4.1.11129.2.4.2";

    private final List<X509Certificate> certificateChain;
    private final List<byte[]> embeddedSCTs;
    private final List<byte[]> tlsExtensionSCTs;
    private final boolean isTLS13;

    /**
     * Parse a Certificate message from raw bytes.
     * @param data The Certificate message body (without handshake header)
     * @param isTLS13 Whether this is a TLS 1.3 Certificate message
     */
    public CertificateMessage(byte[] data, boolean isTLS13) throws TlsException {
        this.isTLS13 = isTLS13;
        this.certificateChain = new ArrayList<>();
        this.embeddedSCTs = new ArrayList<>();
        this.tlsExtensionSCTs = new ArrayList<>();

        if (isTLS13) {
            parseTLS13(data);
        } else {
            parseTLS12(data);
        }
    }

    private void parseTLS12(byte[] data) throws TlsException {
        if (data.length < 3) {
            throw new TlsException("Certificate message too short");
        }

        int ptr = 0;

        // Total certificates length (3 bytes)
        int totalLen = TlsRecordLayer.dec24be(data, ptr);
        ptr += 3;

        if (ptr + totalLen > data.length) {
            throw new TlsException("Certificate message length mismatch");
        }

        int endPtr = ptr + totalLen;

        // Parse each certificate
        while (ptr + 3 <= endPtr) {
            int certLen = TlsRecordLayer.dec24be(data, ptr);
            ptr += 3;

            if (ptr + certLen > endPtr) {
                throw new TlsException("Certificate extends past message boundary");
            }

            byte[] certBytes = new byte[certLen];
            System.arraycopy(data, ptr, certBytes, 0, certLen);
            ptr += certLen;

            X509Certificate cert = parseCertificate(certBytes);
            if (cert != null) {
                certificateChain.add(cert);

                // Extract embedded SCTs from X.509 extension
                byte[] scts = extractEmbeddedSCTs(cert);
                if (scts != null) {
                    embeddedSCTs.add(scts);
                }
            }
        }
    }

    private void parseTLS13(byte[] data) throws TlsException {
        if (data.length < 4) {
            throw new TlsException("Certificate message too short");
        }

        int ptr = 0;

        // certificate_request_context (1 byte length + data)
        int contextLen = data[ptr] & 0xFF;
        ptr += 1 + contextLen;

        if (ptr + 3 > data.length) {
            throw new TlsException("Certificate message too short for certificate list");
        }

        // Certificate list length (3 bytes)
        int listLen = TlsRecordLayer.dec24be(data, ptr);
        ptr += 3;

        if (ptr + listLen > data.length) {
            throw new TlsException("Certificate list length mismatch");
        }

        int endPtr = ptr + listLen;

        // Parse each certificate entry
        while (ptr + 3 <= endPtr) {
            // Certificate data length (3 bytes)
            int certLen = TlsRecordLayer.dec24be(data, ptr);
            ptr += 3;

            if (ptr + certLen > endPtr) {
                throw new TlsException("Certificate extends past list boundary");
            }

            byte[] certBytes = new byte[certLen];
            System.arraycopy(data, ptr, certBytes, 0, certLen);
            ptr += certLen;

            X509Certificate cert = parseCertificate(certBytes);
            if (cert != null) {
                certificateChain.add(cert);

                // Extract embedded SCTs from X.509 extension
                byte[] scts = extractEmbeddedSCTs(cert);
                if (scts != null) {
                    embeddedSCTs.add(scts);
                }
            }

            // Extensions for this certificate (2 bytes length)
            if (ptr + 2 > endPtr) break;
            int extLen = TlsRecordLayer.dec16be(data, ptr);
            ptr += 2;

            if (ptr + extLen > endPtr) break;

            // Parse extensions looking for SCT
            int extEnd = ptr + extLen;
            while (ptr + 4 <= extEnd) {
                int extType = TlsRecordLayer.dec16be(data, ptr);
                ptr += 2;
                int extDataLen = TlsRecordLayer.dec16be(data, ptr);
                ptr += 2;

                if (ptr + extDataLen > extEnd) break;

                if (extType == TlsExtension.SIGNED_CERT_TIMESTAMP) {
                    // Found SCT in TLS extension
                    byte[] sctData = new byte[extDataLen];
                    System.arraycopy(data, ptr, sctData, 0, extDataLen);
                    tlsExtensionSCTs.add(sctData);
                }

                ptr += extDataLen;
            }
        }
    }

    private X509Certificate parseCertificate(byte[] derBytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
        } catch (CertificateException e) {
            return null;
        }
    }

    /**
     * Extract SCTs from X.509 certificate extension (OID 1.3.6.1.4.1.11129.2.4.2).
     * @return Raw SCT list bytes, or null if not present
     */
    private byte[] extractEmbeddedSCTs(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue(SCT_X509_OID);
            if (extValue == null || extValue.length < 4) {
                return null;
            }

            // The extension value is wrapped in an OCTET STRING
            // Skip the ASN.1 OCTET STRING wrapper (typically 04 xx or 04 82 xx xx)
            int ptr = 0;
            if (extValue[ptr] != 0x04) return null; // Should be OCTET STRING
            ptr++;

            int len;
            if ((extValue[ptr] & 0x80) == 0) {
                len = extValue[ptr] & 0x7F;
                ptr++;
            } else {
                int numBytes = extValue[ptr] & 0x7F;
                ptr++;
                len = 0;
                for (int i = 0; i < numBytes; i++) {
                    len = (len << 8) | (extValue[ptr++] & 0xFF);
                }
            }

            // The inner data is the SCT list
            byte[] sctList = new byte[len];
            System.arraycopy(extValue, ptr, sctList, 0, len);
            return sctList;
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== Getters ====================

    /**
     * Get the certificate chain (leaf certificate first).
     */
    public List<X509Certificate> getCertificateChain() {
        return Collections.unmodifiableList(certificateChain);
    }

    /**
     * Get the end-entity (leaf) certificate.
     */
    public X509Certificate getEndEntityCertificate() {
        return certificateChain.isEmpty() ? null : certificateChain.get(0);
    }

    /**
     * Get SCTs embedded in X.509 certificate extensions.
     * Each entry is the raw SCT list bytes.
     */
    public List<byte[]> getEmbeddedSCTs() {
        List<byte[]> result = new ArrayList<>();
        for (byte[] sct : embeddedSCTs) {
            result.add(sct.clone());
        }
        return result;
    }

    /**
     * Get SCTs from TLS extensions (TLS 1.3 only).
     * Each entry is the raw SCT list bytes.
     */
    public List<byte[]> getTlsExtensionSCTs() {
        List<byte[]> result = new ArrayList<>();
        for (byte[] sct : tlsExtensionSCTs) {
            result.add(sct.clone());
        }
        return result;
    }

    /**
     * Get all SCTs from all sources (X.509 extension and TLS extension).
     */
    public List<byte[]> getAllSCTs() {
        List<byte[]> all = new ArrayList<>();
        all.addAll(getEmbeddedSCTs());
        all.addAll(getTlsExtensionSCTs());
        return all;
    }

    /**
     * Check if any SCTs were found.
     */
    public boolean hasSCTs() {
        return !embeddedSCTs.isEmpty() || !tlsExtensionSCTs.isEmpty();
    }

    public boolean isTLS13() {
        return isTLS13;
    }

    /**
     * Get the number of certificates in the chain.
     */
    public int getCertificateCount() {
        return certificateChain.size();
    }

    @Override
    public String toString() {
        X509Certificate leaf = getEndEntityCertificate();
        String subject = leaf != null ? leaf.getSubjectX500Principal().getName() : "none";
        return String.format("CertificateMessage[certs=%d, subject=%s, embeddedSCTs=%d, tlsSCTs=%d]",
                certificateChain.size(), subject, embeddedSCTs.size(), tlsExtensionSCTs.size());
    }
}
