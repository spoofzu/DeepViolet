package com.mps.deepviolet.api.tls;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Aggregated metadata from a TLS handshake.
 * Contains all information extracted during the handshake for analysis.
 */
public class TlsMetadata {

    private final String host;
    private final int port;

    // ServerHello data
    private ServerHello serverHello;

    // Certificate data
    private CertificateMessage certificateMessage;

    // OCSP stapled response (from CertificateStatus message)
    private byte[] stapledOcspResponse;

    // SCTs from OCSP response
    private List<byte[]> ocspSCTs = new ArrayList<>();

    // ServerKeyExchange data
    private ServerKeyExchange serverKeyExchange;

    // Connection metadata
    private long handshakeTimeMs;
    private boolean connectionSucceeded;
    private String failureReason;

    // TLS extensions from ServerHello
    private List<TlsExtension> serverExtensions;

    /** Create metadata for a host.
     *  @param host target hostname
     *  @param port target port */
    public TlsMetadata(String host, int port) {
        this.host = host;
        this.port = port;
        this.serverExtensions = new ArrayList<>();
    }

    // ==================== Setters (package-private) ====================

    void setServerHello(ServerHello serverHello) {
        this.serverHello = serverHello;
        if (serverHello != null) {
            this.serverExtensions = serverHello.getExtensions();
        }
    }

    void setCertificateMessage(CertificateMessage certMsg) {
        this.certificateMessage = certMsg;
    }

    void setServerKeyExchange(ServerKeyExchange ske) {
        this.serverKeyExchange = ske;
    }

    void setStapledOcspResponse(byte[] response) {
        this.stapledOcspResponse = response != null ? response.clone() : null;
    }

    void addOcspSCT(byte[] sct) {
        if (sct != null) {
            ocspSCTs.add(sct.clone());
        }
    }

    void setHandshakeTimeMs(long timeMs) {
        this.handshakeTimeMs = timeMs;
    }

    void setConnectionSucceeded(boolean succeeded) {
        this.connectionSucceeded = succeeded;
    }

    void setFailureReason(String reason) {
        this.failureReason = reason;
    }

    // ==================== Getters ====================

    /** Returns the target hostname.
     *  @return hostname */
    public String getHost() {
        return host;
    }

    /** Returns the target port.
     *  @return port number */
    public int getPort() {
        return port;
    }

    /** Returns the parsed ServerHello.
     *  @return ServerHello, or null */
    public ServerHello getServerHello() {
        return serverHello;
    }

    /** Returns the parsed ServerKeyExchange.
     *  @return ServerKeyExchange, or null */
    public ServerKeyExchange getServerKeyExchange() {
        return serverKeyExchange;
    }

    /** Returns the parsed Certificate message.
     *  @return CertificateMessage, or null */
    public CertificateMessage getCertificateMessage() {
        return certificateMessage;
    }

    /** Returns the stapled OCSP response bytes.
     *  @return copy of OCSP response, or null */
    public byte[] getStapledOcspResponse() {
        return stapledOcspResponse != null ? stapledOcspResponse.clone() : null;
    }

    /** Returns the handshake duration in milliseconds.
     *  @return handshake time */
    public long getHandshakeTimeMs() {
        return handshakeTimeMs;
    }

    /** Returns whether the connection succeeded.
     *  @return true if connection succeeded */
    public boolean isConnectionSucceeded() {
        return connectionSucceeded;
    }

    /** Returns the failure reason, or null on success.
     *  @return failure reason */
    public String getFailureReason() {
        return failureReason;
    }

    // ==================== Derived Getters ====================

    /**
     * Get negotiated TLS version.
     * @return negotiated version code, or -1
     */
    public int getNegotiatedVersion() {
        return serverHello != null ? serverHello.getNegotiatedVersion() : -1;
    }

    /**
     * Get negotiated TLS version as a string.
     * @return version string
     */
    public String getVersionString() {
        return serverHello != null ? serverHello.getVersionString() : "Unknown";
    }

    /**
     * Get negotiated cipher suite.
     * @return cipher suite code, or -1
     */
    public int getCipherSuite() {
        return serverHello != null ? serverHello.getCipherSuite() : -1;
    }

    /**
     * Check if TLS 1.3 was negotiated.
     * @return true if TLS 1.3
     */
    public boolean isTLS13() {
        return serverHello != null && serverHello.isTLS13();
    }

    /**
     * Get server extensions from ServerHello.
     * @return unmodifiable list of extensions
     */
    public List<TlsExtension> getServerExtensions() {
        return Collections.unmodifiableList(serverExtensions);
    }

    /**
     * Get the certificate chain.
     * @return certificate chain list
     */
    public List<X509Certificate> getCertificateChain() {
        if (certificateMessage != null) {
            return certificateMessage.getCertificateChain();
        }
        return Collections.emptyList();
    }

    /**
     * Get the end-entity (leaf) certificate.
     * @return leaf certificate, or null
     */
    public X509Certificate getEndEntityCertificate() {
        if (certificateMessage != null) {
            return certificateMessage.getEndEntityCertificate();
        }
        return null;
    }

    // ==================== SCT Methods ====================

    /**
     * Get all SCTs from all three possible sources:
     * 1. TLS extension in ServerHello (type 0x0012)
     * 2. X.509 extension in certificates
     * 3. OCSP stapled response
     * @return list of all SCT byte arrays
     */
    public List<byte[]> getAllSCTs() {
        List<byte[]> allSCTs = new ArrayList<>();

        // Source 1: TLS extension in ServerHello
        if (serverHello != null && serverHello.hasExtension(TlsExtension.SIGNED_CERT_TIMESTAMP)) {
            byte[] tlsSCT = serverHello.getExtensionData(TlsExtension.SIGNED_CERT_TIMESTAMP);
            if (tlsSCT != null) {
                allSCTs.add(tlsSCT);
            }
        }

        // Source 2: X.509 extensions in certificates
        if (certificateMessage != null) {
            allSCTs.addAll(certificateMessage.getAllSCTs());
        }

        // Source 3: OCSP stapled response
        for (byte[] sct : ocspSCTs) {
            allSCTs.add(sct.clone());
        }

        return allSCTs;
    }

    /**
     * Get SCTs from TLS ServerHello extension.
     * @return SCT bytes, or null
     */
    public byte[] getTlsExtensionSCT() {
        if (serverHello != null) {
            return serverHello.getExtensionData(TlsExtension.SIGNED_CERT_TIMESTAMP);
        }
        return null;
    }

    /**
     * Get SCTs embedded in X.509 certificates.
     * @return list of embedded SCT byte arrays
     */
    public List<byte[]> getCertificateSCTs() {
        if (certificateMessage != null) {
            return certificateMessage.getEmbeddedSCTs();
        }
        return Collections.emptyList();
    }

    /**
     * Get SCTs from OCSP stapled response.
     * @return list of OCSP SCT byte arrays
     */
    public List<byte[]> getOcspSCTs() {
        List<byte[]> result = new ArrayList<>();
        for (byte[] sct : ocspSCTs) {
            result.add(sct.clone());
        }
        return result;
    }

    /**
     * Check if any SCTs were found.
     * @return true if SCTs are present
     */
    public boolean hasSCTs() {
        return !getAllSCTs().isEmpty();
    }

    // ==================== Fingerprint Support ====================

    /**
     * Get the fingerprint code for this handshake.
     * Returns a 3-character code representing cipher, version, and extension count.
     *
     * @return 3-character fingerprint code, or "|||" if no response
     */
    public String getFingerprintCode() {
        if (serverHello == null) {
            return "|||"; // No response
        }
        return serverHello.getFingerprintCode();
    }

    // ==================== OCSP Stapling ====================

    /**
     * Check if OCSP stapling response was received.
     * @return true if a stapled OCSP response is present
     */
    public boolean hasStapledOcspResponse() {
        return stapledOcspResponse != null && stapledOcspResponse.length > 0;
    }

    // ==================== Utility ====================

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("TlsMetadata[");
        sb.append("host=").append(host).append(":").append(port);
        sb.append(", success=").append(connectionSucceeded);

        if (connectionSucceeded && serverHello != null) {
            sb.append(", version=").append(getVersionString());
            sb.append(", cipher=").append(serverHello.getCipherSuiteHex());
            sb.append(", extensions=").append(serverExtensions.size());
            sb.append(", hasCerts=").append(certificateMessage != null);
            sb.append(", hasOCSP=").append(hasStapledOcspResponse());
            sb.append(", hasSCTs=").append(hasSCTs());
        } else if (failureReason != null) {
            sb.append(", failure=").append(failureReason);
        }

        sb.append("]");
        return sb.toString();
    }
}
