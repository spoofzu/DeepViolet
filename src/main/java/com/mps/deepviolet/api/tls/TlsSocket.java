package com.mps.deepviolet.api.tls;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyFactory;
import javax.crypto.KeyAgreement;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pure raw TLS socket implementation for TLS handshake analysis.
 *
 * This class provides full access to TLS metadata without using JSSE,
 * enabling TLS server fingerprinting, SCT extraction, and complete handshake analysis.
 *
 * Features:
 * - Configurable ClientHello (for behavior probes)
 * - Full ServerHello parsing with ALL extensions
 * - Certificate chain extraction
 * - OCSP stapling support
 * - SCT extraction from all sources
 * - No encryption (analysis-only)
 *
 * Usage:
 * <pre>
 * try (TlsSocket socket = new TlsSocket("example.com", 443)) {
 *     TlsMetadata metadata = socket.performHandshake();
 *     System.out.println(metadata.getVersionString());
 *     System.out.println(metadata.getCipherSuite());
 * }
 * </pre>
 */
public class TlsSocket implements Closeable {

    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.tls.TlsSocket");

    private static final int DEFAULT_TIMEOUT_MS = 10000;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 5000;

    /** Total time budget for PQ probe retries (milliseconds). */
    private static final long PQ_RETRY_BUDGET_MS = 10_000;
    /** Delay between PQ probe retry attempts (milliseconds). */
    private static final long PQ_RETRY_DELAY_MS = 2_000;

    private final String host;
    private final int port;
    private Socket socket;
    private TlsRecordLayer recordLayer;

    private ClientHelloConfig clientHelloConfig;
    private TlsMetadata metadata;

    private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
    private int readTimeoutMs = DEFAULT_TIMEOUT_MS;

    /**
     * Create a TlsSocket for the given host and port.
     * @param host target hostname
     * @param port target port
     */
    public TlsSocket(String host, int port) {
        this.host = host;
        this.port = port;
        this.clientHelloConfig = ClientHelloConfig.defaultConfig();
    }

    /**
     * Create a TlsSocket from an InetSocketAddress.
     * @param address socket address
     */
    public TlsSocket(InetSocketAddress address) {
        this(address.getHostName(), address.getPort());
    }

    // ==================== Configuration ====================

    /**
     * Set the ClientHello configuration for the handshake.
     * @param config client hello configuration
     */
    public void setClientHelloConfig(ClientHelloConfig config) {
        this.clientHelloConfig = config != null ? config : ClientHelloConfig.defaultConfig();
    }

    /**
     * Set connection timeout in milliseconds.
     * @param timeout timeout in milliseconds
     */
    public void setConnectTimeoutMs(int timeout) {
        this.connectTimeoutMs = timeout;
    }

    /**
     * Set read timeout in milliseconds.
     * @param timeout timeout in milliseconds
     */
    public void setReadTimeoutMs(int timeout) {
        this.readTimeoutMs = timeout;
    }

    // ==================== Handshake ====================

    /**
     * Perform the TLS handshake and return collected metadata.
     * This only performs the unencrypted portion of the handshake.
     *
     * @return Metadata collected from the handshake
     * @throws TlsException on TLS protocol errors
     * @throws IOException on network errors
     */
    public TlsMetadata performHandshake() throws TlsException, IOException {
        long startTime = System.currentTimeMillis();
        metadata = new TlsMetadata(host, port);

        try {
            // Connect
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);

            recordLayer = new TlsRecordLayer(socket.getInputStream(), socket.getOutputStream());

            // Send ClientHello
            ClientHello clientHello = new ClientHello(clientHelloConfig, host);
            byte[] clientHelloBytes = clientHello.build();

            recordLayer.setOutputType(TlsRecordLayer.HANDSHAKE);
            recordLayer.setOutputVersion(clientHello.getRecordVersion());
            recordLayer.write(clientHelloBytes);
            recordLayer.flushOutput();

            // Read ServerHello
            TlsRecordLayer.HandshakeMessage shMsg = recordLayer.readHandshakeMessage();
            if (shMsg.getType() != TlsRecordLayer.HANDSHAKE_SERVER_HELLO) {
                throw new TlsException("Expected ServerHello, got: " + shMsg.getTypeName());
            }

            ServerHello serverHello = new ServerHello(shMsg.getData(), shMsg.getRecordVersion());
            metadata.setServerHello(serverHello);

            if (serverHello.isTLS13()) {
                // TLS 1.3: decrypt handshake to extract certificates
                // Reconstruct ServerHello handshake message bytes (type + length + body)
                byte[] shBody = shMsg.getData();
                byte[] serverHelloHandshakeBytes = new byte[4 + shBody.length];
                serverHelloHandshakeBytes[0] = (byte) TlsRecordLayer.HANDSHAKE_SERVER_HELLO;
                TlsRecordLayer.enc24be(shBody.length, serverHelloHandshakeBytes, 1);
                System.arraycopy(shBody, 0, serverHelloHandshakeBytes, 4, shBody.length);

                readTls13Handshake(clientHello, clientHelloBytes, serverHello, serverHelloHandshakeBytes);
            } else {
                // Continue reading TLS 1.2 handshake messages
                readTls12Handshake();
            }

            metadata.setConnectionSucceeded(true);
            metadata.setHandshakeTimeMs(System.currentTimeMillis() - startTime);

        } catch (EOFException e) {
            metadata.setConnectionSucceeded(false);
            metadata.setFailureReason("Connection closed by server");
        } catch (SocketTimeoutException e) {
            metadata.setConnectionSucceeded(false);
            metadata.setFailureReason("Connection timeout");
        } catch (TlsException e) {
            metadata.setConnectionSucceeded(false);
            metadata.setFailureReason(e.getMessage());
            throw e;
        } catch (IOException e) {
            metadata.setConnectionSucceeded(false);
            metadata.setFailureReason("IO error: " + e.getMessage());
            throw e;
        }

        return metadata;
    }

    /**
     * Read remaining TLS 1.2 handshake messages (Certificate, CertificateStatus, etc.)
     */
    private void readTls12Handshake() throws TlsException, IOException {
        try {
            while (true) {
                TlsRecordLayer.HandshakeMessage msg = recordLayer.readHandshakeMessage();

                switch (msg.getType()) {
                    case TlsRecordLayer.HANDSHAKE_CERTIFICATE:
                        CertificateMessage certMsg = new CertificateMessage(msg.getData(), false);
                        metadata.setCertificateMessage(certMsg);
                        break;

                    case TlsRecordLayer.HANDSHAKE_CERTIFICATE_STATUS:
                        // OCSP stapled response
                        parseOcspResponse(msg.getData());
                        break;

                    case TlsRecordLayer.HANDSHAKE_SERVER_HELLO_DONE:
                        // Done with unencrypted portion
                        return;

                    case TlsRecordLayer.HANDSHAKE_SERVER_KEY_EXCHANGE:
                        // Parse ServerKeyExchange for DH/ECDHE parameters
                        int cipherSuite = metadata.getServerHello() != null
                                ? metadata.getServerHello().getCipherSuite() : 0;
                        ServerKeyExchange ske = ServerKeyExchange.parse(msg.getData(), cipherSuite);
                        metadata.setServerKeyExchange(ske);
                        break;

                    case TlsRecordLayer.HANDSHAKE_CERTIFICATE_REQUEST:
                        // Skip CertificateRequest
                        break;

                    default:
                        // Unknown message type, stop
                        return;
                }
            }
        } catch (EOFException e) {
            // Connection closed, which is okay after we got what we need
        } catch (TlsException e) {
            if (!e.isAlertException()) {
                throw e;
            }
            // Alerts are expected after we don't complete the handshake
        }
    }

    /**
     * Read and decrypt TLS 1.3 handshake messages to extract certificates.
     *
     * <p>Performs ECDH key agreement with the server's key share, derives
     * handshake traffic keys via HKDF, and decrypts the encrypted handshake
     * records to find the Certificate message.</p>
     *
     * @param clientHello The ClientHello builder (for key pairs)
     * @param clientHelloBytes Raw ClientHello handshake message bytes (type + length + body)
     * @param serverHello Parsed ServerHello
     * @param serverHelloBytes Raw ServerHello handshake message bytes (type + length + body)
     */
    private void readTls13Handshake(ClientHello clientHello, byte[] clientHelloBytes,
                                     ServerHello serverHello, byte[] serverHelloBytes)
            throws TlsException, IOException {
        try {
            // Step 1: ECDH key agreement
            int group = serverHello.getKeyShareGroup();
            byte[] serverPubBytes = serverHello.getKeySharePublicKey();
            if (group < 0 || serverPubBytes == null) {
                logger.debug("TLS 1.3: no key_share in ServerHello, cannot decrypt");
                return;
            }

            byte[] sharedSecret;
            if (group == 0x001d) { // X25519
                sharedSecret = computeX25519SharedSecret(clientHello, serverPubBytes);
            } else if (group == 0x0017) { // secp256r1
                sharedSecret = computeSecp256r1SharedSecret(clientHello, serverPubBytes);
            } else {
                logger.debug("TLS 1.3: unsupported key share group 0x{}", Integer.toHexString(group));
                return;
            }

            // Step 2: Compute transcript hash = Hash(ClientHello || ServerHello)
            String hashAlgo = Tls13KeySchedule.hashAlgorithm(serverHello.getCipherSuite());
            MessageDigest md = MessageDigest.getInstance(hashAlgo);
            md.update(clientHelloBytes);
            md.update(serverHelloBytes);
            byte[] transcriptHash = md.digest();

            // Step 3: Derive handshake traffic keys
            Tls13KeySchedule.TrafficKeys keys = Tls13KeySchedule.deriveHandshakeKeys(
                    sharedSecret, transcriptHash, serverHello.getCipherSuite());

            // Step 4: Read and decrypt handshake records
            long seqNum = 0;
            boolean done = false;

            while (!done) {
                byte[] record = recordLayer.readRecord();
                byte[] recordHeader = recordLayer.getLastRecordHeader();
                int recordType = recordLayer.getInputType();

                // Skip optional ChangeCipherSpec (TLS 1.3 middlebox compatibility)
                if (recordType == TlsRecordLayer.CHANGE_CIPHER_SPEC) {
                    continue;
                }

                // Must be APPLICATION_DATA (encrypted handshake)
                if (recordType != TlsRecordLayer.APPLICATION_DATA) {
                    logger.debug("TLS 1.3: unexpected record type {} during handshake",
                            recordType);
                    continue;
                }

                Tls13RecordProtection.DecryptedRecord dec =
                        Tls13RecordProtection.decryptRecord(record, recordHeader, seqNum++, keys);

                if (dec.contentType() != TlsRecordLayer.HANDSHAKE) {
                    // Could be alerts or other content types
                    if (dec.contentType() == TlsRecordLayer.ALERT && dec.data().length >= 2) {
                        int alertDesc = dec.data()[1] & 0xFF;
                        logger.debug("TLS 1.3: received alert {} during handshake", alertDesc);
                    }
                    continue;
                }

                // Parse handshake message(s) — multiple may be coalesced in one record
                done = parseDecryptedHandshake(dec.data());
            }

        } catch (TlsException e) {
            throw e;
        } catch (Exception e) {
            logger.debug("TLS 1.3 handshake decryption failed: {}", e.getMessage());
            // Non-fatal: we still have ServerHello metadata even without certs
        }
    }

    /**
     * Parse one or more handshake messages from decrypted TLS 1.3 data.
     * @return true if Finished message was seen (handshake complete)
     */
    private boolean parseDecryptedHandshake(byte[] data) throws TlsException {
        int ptr = 0;
        while (ptr + 4 <= data.length) {
            int msgType = data[ptr] & 0xFF;
            int msgLen = TlsRecordLayer.dec24be(data, ptr + 1);
            ptr += 4;

            if (ptr + msgLen > data.length) {
                break;
            }

            byte[] msgBody = Arrays.copyOfRange(data, ptr, ptr + msgLen);
            ptr += msgLen;

            switch (msgType) {
                case TlsRecordLayer.HANDSHAKE_ENCRYPTED_EXTENSIONS:
                    // Skip — not needed for certificate extraction
                    break;

                case TlsRecordLayer.HANDSHAKE_CERTIFICATE:
                    CertificateMessage certMsg = new CertificateMessage(msgBody, true);
                    metadata.setCertificateMessage(certMsg);
                    break;

                case TlsRecordLayer.HANDSHAKE_CERTIFICATE_REQUEST:
                    // Skip
                    break;

                case TlsRecordLayer.HANDSHAKE_CERTIFICATE_VERIFY:
                    // Skip — we don't need to verify the server's signature
                    break;

                case TlsRecordLayer.HANDSHAKE_FINISHED:
                    return true;

                default:
                    break;
            }
        }
        return false;
    }

    /**
     * Compute shared secret using X25519 key agreement.
     */
    private byte[] computeX25519SharedSecret(ClientHello clientHello, byte[] serverPubBytes)
            throws Exception {
        if (clientHello.getX25519KeyPair() == null) {
            throw new TlsException("Server selected X25519 but no X25519 key pair was generated");
        }

        // Wrap raw 32-byte X25519 public key in X.509 SubjectPublicKeyInfo format
        // X25519 OID: 1.3.101.110
        byte[] x509Prefix = {
            0x30, 0x2a,       // SEQUENCE, 42 bytes
            0x30, 0x05,       // SEQUENCE, 5 bytes (AlgorithmIdentifier)
            0x06, 0x03,       //   OID, 3 bytes
            0x2b, 0x65, 0x6e, //   1.3.101.110 (X25519)
            0x03, 0x21,       // BIT STRING, 33 bytes
            0x00              // no unused bits
        };
        byte[] x509Encoded = new byte[x509Prefix.length + serverPubBytes.length];
        System.arraycopy(x509Prefix, 0, x509Encoded, 0, x509Prefix.length);
        System.arraycopy(serverPubBytes, 0, x509Encoded, x509Prefix.length, serverPubBytes.length);

        KeyFactory kf = KeyFactory.getInstance("X25519");
        java.security.PublicKey serverPub = kf.generatePublic(new X509EncodedKeySpec(x509Encoded));

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(clientHello.getX25519KeyPair().getPrivate());
        ka.doPhase(serverPub, true);
        return ka.generateSecret();
    }

    /**
     * Compute shared secret using secp256r1 (ECDH) key agreement.
     */
    private byte[] computeSecp256r1SharedSecret(ClientHello clientHello, byte[] serverPubBytes)
            throws Exception {
        if (clientHello.getKeyShareKeyPair() == null) {
            throw new TlsException("Server selected secp256r1 but no EC key pair was generated");
        }

        // Parse uncompressed point: 04 || x[32] || y[32]
        if (serverPubBytes.length != 65 || serverPubBytes[0] != 0x04) {
            throw new TlsException("Invalid secp256r1 public key from server");
        }

        byte[] xBytes = Arrays.copyOfRange(serverPubBytes, 1, 33);
        byte[] yBytes = Arrays.copyOfRange(serverPubBytes, 33, 65);
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        ECParameterSpec ecSpec = ((ECPublicKey) clientHello.getKeyShareKeyPair().getPublic())
                .getParams();
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(new ECPoint(x, y), ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        java.security.PublicKey serverPub = kf.generatePublic(pubSpec);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(clientHello.getKeyShareKeyPair().getPrivate());
        ka.doPhase(serverPub, true);
        return ka.generateSecret();
    }

    /**
     * Parse OCSP stapled response from CertificateStatus message.
     */
    private void parseOcspResponse(byte[] data) {
        if (data.length < 4) return;

        // CertificateStatus structure:
        // 1 byte: status_type (1 = OCSP)
        // 3 bytes: response length
        // response data
        int statusType = data[0] & 0xFF;
        if (statusType != 1) return; // Not OCSP

        int responseLen = TlsRecordLayer.dec24be(data, 1);
        if (4 + responseLen > data.length) return;

        byte[] ocspResponse = new byte[responseLen];
        System.arraycopy(data, 4, ocspResponse, 0, responseLen);
        metadata.setStapledOcspResponse(ocspResponse);

        // TODO: Parse SCTs from OCSP response
        // This requires parsing the OCSP response ASN.1 structure
        // to find the SCT extension (OID 1.3.6.1.4.1.11129.2.4.5)
    }

    // ==================== Metadata Access ====================

    /**
     * Get the metadata from the last handshake.
     * @return TLS metadata, or null
     */
    public TlsMetadata getMetadata() {
        return metadata;
    }

    /**
     * Get the ServerHello from the last handshake.
     * @return ServerHello, or null
     */
    public ServerHello getServerHello() {
        return metadata != null ? metadata.getServerHello() : null;
    }

    /**
     * Get server extensions from the last handshake.
     * @return list of extensions, or null
     */
    public List<TlsExtension> getServerExtensions() {
        return metadata != null ? metadata.getServerExtensions() : null;
    }

    /**
     * Get the certificate message from the last handshake.
     * @return CertificateMessage, or null
     */
    public CertificateMessage getCertificateMessage() {
        return metadata != null ? metadata.getCertificateMessage() : null;
    }

    /**
     * Get the stapled OCSP response from the last handshake.
     * @return OCSP response bytes, or null
     */
    public byte[] getStapledOcspResponse() {
        return metadata != null ? metadata.getStapledOcspResponse() : null;
    }

    /**
     * Get all SCTs from all sources.
     * @return list of SCT byte arrays, or null
     */
    public List<byte[]> getSCTs() {
        return metadata != null ? metadata.getAllSCTs() : null;
    }

    // ==================== Socket Properties ====================

    /**
     * Get the receive buffer size.
     * @return buffer size, or -1 if not connected
     * @throws IOException on socket errors
     */
    public int getReceiveBufferSize() throws IOException {
        return socket != null ? socket.getReceiveBufferSize() : -1;
    }

    /**
     * Get TCP keep-alive setting.
     * @return true if keep-alive is enabled
     * @throws IOException on socket errors
     */
    public boolean getKeepAlive() throws IOException {
        return socket != null && socket.getKeepAlive();
    }

    /**
     * Check if socket is connected.
     * @return true if connected
     */
    public boolean isConnected() {
        return socket != null && socket.isConnected();
    }

    /**
     * Check if socket is closed.
     * @return true if closed
     */
    public boolean isClosed() {
        return socket == null || socket.isClosed();
    }

    // ==================== TLS Fingerprint Support ====================

    /**
     * Compute TLS server fingerprint for a host.
     * This sends 10 different ClientHello probes and combines the responses
     * to create a fingerprint that characterizes the server's TLS behavior.
     *
     * @param host Target hostname
     * @param port Target port
     * @return 30-character TLS probe fingerprint
     * @see com.mps.deepviolet.api.fingerprint.TlsServerFingerprint
     */
    public static String computeTlsFingerprint(String host, int port) {
        return com.mps.deepviolet.api.fingerprint.TlsServerFingerprint.compute(host, port);
    }

    /**
     * Compute TLS server fingerprint for a host with default HTTPS port.
     *
     * @param host Target hostname
     * @return 30-character TLS probe fingerprint
     */
    public static String computeTlsFingerprint(String host) {
        return computeTlsFingerprint(host, 443);
    }

    // ==================== Quick Connect Methods ====================

    /**
     * Quick method to connect and get metadata.
     * @param host target hostname
     * @param port target port
     * @return TLS metadata from the handshake
     * @throws TlsException on TLS errors
     * @throws IOException on I/O errors
     */
    public static TlsMetadata connect(String host, int port) throws TlsException, IOException {
        try (TlsSocket socket = new TlsSocket(host, port)) {
            return socket.performHandshake();
        }
    }

    /**
     * Quick method to connect with custom configuration.
     * @param host target hostname
     * @param port target port
     * @param config client hello configuration
     * @return TLS metadata from the handshake
     * @throws TlsException on TLS errors
     * @throws IOException on I/O errors
     */
    public static TlsMetadata connect(String host, int port, ClientHelloConfig config)
            throws TlsException, IOException {
        try (TlsSocket socket = new TlsSocket(host, port)) {
            socket.setClientHelloConfig(config);
            return socket.performHandshake();
        }
    }

    /**
     * Quick method to get certificate chain.
     * @param host target hostname
     * @param port target port
     * @return certificate chain list
     * @throws TlsException on TLS errors
     * @throws IOException on I/O errors
     */
    public static List<X509Certificate> getCertificateChain(String host, int port)
            throws TlsException, IOException {
        TlsMetadata metadata = connect(host, port);
        return metadata.getCertificateChain();
    }

    // ==================== Fallback SCSV Probe ====================

    /**
     * Test whether the server supports TLS_FALLBACK_SCSV (RFC 7507).
     *
     * <p>Sends a TLS 1.1 ClientHello with the TLS_FALLBACK_SCSV sentinel
     * cipher (0x5600) included. If the server responds with an
     * inappropriate_fallback alert (alert description 86), SCSV is supported.</p>
     *
     * @param host Target hostname
     * @param port Target port
     * @return true if SCSV is supported, false if not, null if test was inconclusive
     */
    public static Boolean testFallbackScsv(String host, int port) {
        try {
            // Build a TLS 1.1 ClientHello with the SCSV sentinel cipher
            ClientHelloConfig config = new ClientHelloConfig()
                    .setTlsVersion(ClientHelloConfig.TLS_1_1)
                    .setCipherSuites(java.util.Arrays.asList(
                            0x002F,  // TLS_RSA_WITH_AES_128_CBC_SHA
                            0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
                            0x5600   // TLS_FALLBACK_SCSV
                    ))
                    .setIncludeSupportedVersions(false)
                    .setIncludeSignatureAlgorithms(false)
                    .setIncludeSupportedGroups(false)
                    .setIncludeKeyShare(false)
                    .setIncludeGrease(false);

            try (TlsSocket socket = new TlsSocket(host, port)) {
                socket.setClientHelloConfig(config);
                socket.setConnectTimeoutMs(5000);
                socket.setReadTimeoutMs(5000);
                socket.performHandshake();
                // If handshake succeeds, server doesn't check SCSV
                // (it accepted TLS 1.1 with the fallback cipher without complaining)
                return false;
            }
        } catch (TlsException e) {
            // Check if it's an inappropriate_fallback alert (description 86)
            if (e.isAlertException() && e.getAlertDescription() == 86) {
                return true; // Server supports SCSV
            }
            // Other TLS error — could be various reasons
            return null;
        } catch (Exception e) {
            return null; // Inconclusive
        }
    }

    // ==================== Post-Quantum Probe ====================

    /**
     * Test which post-quantum key exchange groups the server supports.
     *
     * <p>Probes each known PQ group individually by sending a TLS 1.3
     * ClientHello that advertises one PQ group in {@code supported_groups}
     * with an empty {@code key_share} list.  The empty key_share forces
     * the server to respond with a HelloRetryRequest naming its preferred
     * group.  If the HRR names the PQ group, that group is supported.</p>
     *
     * <p>On inconclusive results (network error, timeout) the probe is
     * retried up to the {@link #PQ_RETRY_BUDGET_MS} time budget before
     * giving up.</p>
     *
     * @param host Target hostname
     * @param port Target port
     * @return list of supported PQ group codes (may be empty), or null if
     *         the test was inconclusive (e.g. non-TLS 1.3 server)
     */
    public static java.util.List<Integer> testPqSupport(String host, int port) {
        long deadline = System.currentTimeMillis() + PQ_RETRY_BUDGET_MS;
        java.util.List<Integer> result = null;
        int attempt = 0;

        while (true) {
            attempt++;
            result = testPqSupportOnce(host, port);
            if (result != null) return result;

            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= PQ_RETRY_DELAY_MS) break;

            logger.debug("PQ support probe inconclusive (attempt {}), retrying in {}ms",
                    attempt, PQ_RETRY_DELAY_MS);
            try {
                Thread.sleep(PQ_RETRY_DELAY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        logger.info("PQ support probe inconclusive after {} attempt(s) for {}:{}",
                attempt, host, port);
        return null;
    }

    /**
     * Single attempt at testing PQ group support (no retries).
     */
    private static java.util.List<Integer> testPqSupportOnce(String host, int port) {
        java.util.List<Integer> supported = new java.util.ArrayList<>();
        boolean anyProbeRan = false;

        for (int pqGroup : NamedGroup.PQ_GROUPS) {
            Boolean result = testPqGroupSupport(host, port, pqGroup);
            if (result == null && !anyProbeRan) {
                // First probe inconclusive (non-TLS 1.3, network error) — bail out
                return null;
            }
            anyProbeRan = true;
            if (Boolean.TRUE.equals(result)) {
                supported.add(pqGroup);
            }
        }
        return supported;
    }

    /**
     * Test whether the server supports a single post-quantum key exchange group.
     *
     * @param host     Target hostname
     * @param port     Target port
     * @param pqGroup  The PQ named-group code to test
     * @return true if supported, false if not, null if inconclusive
     */
    static Boolean testPqGroupSupport(String host, int port, int pqGroup) {
        try {
            ClientHelloConfig config = ClientHelloConfig.pqProbe(pqGroup);

            try (TlsSocket socket = new TlsSocket(host, port)) {
                socket.setClientHelloConfig(config);
                socket.setConnectTimeoutMs(5000);
                socket.setReadTimeoutMs(5000);

                // Connect and send ClientHello manually (performHandshake does
                // too much work; we just need the first ServerHello/HRR)
                socket.socket = new java.net.Socket();
                socket.socket.connect(new java.net.InetSocketAddress(host, port), socket.connectTimeoutMs);
                socket.socket.setSoTimeout(socket.readTimeoutMs);

                socket.recordLayer = new TlsRecordLayer(
                        socket.socket.getInputStream(),
                        socket.socket.getOutputStream());

                ClientHello clientHello = new ClientHello(config, host);
                byte[] clientHelloBytes = clientHello.build();

                socket.recordLayer.setOutputType(TlsRecordLayer.HANDSHAKE);
                socket.recordLayer.setOutputVersion(clientHello.getRecordVersion());
                socket.recordLayer.write(clientHelloBytes);
                socket.recordLayer.flushOutput();

                // Read the response
                TlsRecordLayer.HandshakeMessage msg = socket.recordLayer.readHandshakeMessage();
                if (msg.getType() != TlsRecordLayer.HANDSHAKE_SERVER_HELLO) {
                    return null; // Unexpected response
                }

                ServerHello serverHello = new ServerHello(msg.getData(), msg.getRecordVersion());

                // Non-TLS 1.3 server — PQ not applicable
                if (!serverHello.isTLS13()) {
                    return null;
                }

                int selectedGroup = serverHello.getKeyShareGroup();

                // Server selected the PQ group (via HRR or directly)
                if (selectedGroup == pqGroup) {
                    return true;
                }

                // Server selected a different group (shouldn't happen with
                // a single-group offer, but handle defensively)
                return false;
            }
        } catch (TlsException e) {
            // TLS alert (e.g. handshake_failure) — server is TLS 1.3
            // but does not support this PQ group
            return false;
        } catch (Exception e) {
            // Network error, timeout, etc. — inconclusive
            return null;
        }
    }

    // ==================== Post-Quantum Preference Probe ====================

    /**
     * Test which key exchange group the server prefers when offered both
     * PQ hybrid and classical groups.
     *
     * <p>Sends a TLS 1.3 ClientHello with PQ hybrid groups listed before
     * classical groups and an empty {@code key_share} (forcing HRR).
     * The server's HelloRetryRequest reveals its preferred group.</p>
     *
     * <p>On inconclusive results the probe is retried up to the
     * {@link #PQ_RETRY_BUDGET_MS} time budget before giving up.</p>
     *
     * @param host Target hostname
     * @param port Target port
     * @return the selected group code (IANA named-group), or null if
     *         inconclusive (non-TLS 1.3, network error)
     */
    public static Integer testPqPreference(String host, int port) {
        long deadline = System.currentTimeMillis() + PQ_RETRY_BUDGET_MS;
        Integer result = null;
        int attempt = 0;

        while (true) {
            attempt++;
            result = testPqPreferenceOnce(host, port);
            if (result != null) return result;

            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= PQ_RETRY_DELAY_MS) break;

            logger.debug("PQ preference probe inconclusive (attempt {}), retrying in {}ms",
                    attempt, PQ_RETRY_DELAY_MS);
            try {
                Thread.sleep(PQ_RETRY_DELAY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        logger.info("PQ preference probe inconclusive after {} attempt(s) for {}:{}",
                attempt, host, port);
        return null;
    }

    /**
     * Single attempt at testing PQ preference (no retries).
     */
    private static Integer testPqPreferenceOnce(String host, int port) {
        try {
            ClientHelloConfig config = ClientHelloConfig.pqPreferenceProbe();

            try (TlsSocket socket = new TlsSocket(host, port)) {
                socket.setClientHelloConfig(config);
                socket.setConnectTimeoutMs(5000);
                socket.setReadTimeoutMs(5000);

                socket.socket = new java.net.Socket();
                socket.socket.connect(new java.net.InetSocketAddress(host, port), socket.connectTimeoutMs);
                socket.socket.setSoTimeout(socket.readTimeoutMs);

                socket.recordLayer = new TlsRecordLayer(
                        socket.socket.getInputStream(),
                        socket.socket.getOutputStream());

                ClientHello clientHello = new ClientHello(config, host);
                byte[] clientHelloBytes = clientHello.build();

                socket.recordLayer.setOutputType(TlsRecordLayer.HANDSHAKE);
                socket.recordLayer.setOutputVersion(clientHello.getRecordVersion());
                socket.recordLayer.write(clientHelloBytes);
                socket.recordLayer.flushOutput();

                TlsRecordLayer.HandshakeMessage msg = socket.recordLayer.readHandshakeMessage();
                if (msg.getType() != TlsRecordLayer.HANDSHAKE_SERVER_HELLO) {
                    return null;
                }

                ServerHello serverHello = new ServerHello(msg.getData(), msg.getRecordVersion());

                if (!serverHello.isTLS13()) {
                    return null;
                }

                int selectedGroup = serverHello.getKeyShareGroup();
                return selectedGroup >= 0 ? selectedGroup : null;
            }
        } catch (TlsException e) {
            // TLS alert — server couldn't negotiate with our offer
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== Closeable ====================

    @Override
    public void close() throws IOException {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }
}
