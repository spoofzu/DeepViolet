package com.mps.deepviolet.api.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.List;

/**
 * Builder for TLS ClientHello messages.
 * Generates ClientHello bytes based on ClientHelloConfig.
 *
 * The ClientHello structure (RFC 5246 / RFC 8446):
 * - handshake type: 1 byte (0x01 = ClientHello)
 * - length: 3 bytes
 * - version: 2 bytes (legacy, always 0x0303 for TLS 1.3)
 * - random: 32 bytes
 * - session_id: 1 byte length + data
 * - cipher_suites: 2 byte length + list
 * - compression_methods: 1 byte length + list
 * - extensions: 2 byte length + list
 */
public class ClientHello {

    private static final SecureRandom RNG = new SecureRandom();

    private final ClientHelloConfig config;
    private final String hostname;
    private byte[] clientRandom;
    private byte[] sessionId;
    private KeyPair keyShareKeyPair;   // secp256r1
    private KeyPair x25519KeyPair;     // X25519

    public ClientHello(ClientHelloConfig config, String hostname) {
        this.config = config;
        this.hostname = hostname;
        this.clientRandom = new byte[32];
        RNG.nextBytes(clientRandom);
        // Put timestamp in first 4 bytes (per TLS spec, though often random now)
        TlsRecordLayer.enc32be((int) (System.currentTimeMillis() / 1000), clientRandom, 0);
        this.sessionId = new byte[0]; // Empty session ID
    }

    /**
     * Get the client random bytes (32 bytes).
     */
    public byte[] getClientRandom() {
        return clientRandom.clone();
    }

    /**
     * Set custom client random bytes.
     */
    public void setClientRandom(byte[] random) {
        if (random.length != 32) {
            throw new IllegalArgumentException("Client random must be 32 bytes");
        }
        this.clientRandom = random.clone();
    }

    /**
     * Get the session ID.
     */
    public byte[] getSessionId() {
        return sessionId.clone();
    }

    /**
     * Set session ID (for session resumption testing).
     */
    public void setSessionId(byte[] id) {
        this.sessionId = id != null ? id.clone() : new byte[0];
    }

    /**
     * Get the EC key pair used for key_share extension (TLS 1.3, secp256r1).
     * Returns null if key_share was not included.
     */
    public KeyPair getKeyShareKeyPair() {
        return keyShareKeyPair;
    }

    /**
     * Get the X25519 key pair used for key_share extension (TLS 1.3).
     * Returns null if X25519 key share was not included.
     */
    public KeyPair getX25519KeyPair() {
        return x25519KeyPair;
    }

    /**
     * Build the ClientHello message bytes.
     * @return Complete ClientHello handshake message
     */
    public byte[] build() {
        try {
            return buildClientHello();
        } catch (IOException e) {
            throw new RuntimeException("Failed to build ClientHello", e);
        }
    }

    private byte[] buildClientHello() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();

        // Handshake message header: type (1) + length placeholder (3)
        b.write(0x01); // ClientHello
        b.write(0); b.write(0); b.write(0); // Length placeholder

        // Version: For TLS 1.3, use 0x0303 (TLS 1.2) as legacy version
        int version = config.getTlsVersion();
        int legacyVersion = (version >= ClientHelloConfig.TLS_1_3) ? 0x0303 : version;
        b.write(legacyVersion >>> 8);
        b.write(legacyVersion);

        // Client random (32 bytes)
        b.write(clientRandom);

        // Session ID
        b.write(sessionId.length);
        if (sessionId.length > 0) {
            b.write(sessionId);
        }

        // Cipher suites
        writeCipherSuites(b, config.getCipherSuites(), config.isIncludeGrease());

        // Compression methods
        if (version >= ClientHelloConfig.TLS_1_3) {
            // TLS 1.3: only null compression
            b.write(1);  // 1 method
            b.write(0);  // null compression
        } else {
            // Older versions: null and deflate for CRIME detection
            b.write(2);  // 2 methods
            b.write(1);  // deflate
            b.write(0);  // null
        }

        // Extensions
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeExtensions(extensions);
        byte[] extBytes = extensions.toByteArray();
        TlsRecordLayer.enc16be(extBytes.length, b);
        b.write(extBytes);

        // Fix up the length in header
        byte[] msg = b.toByteArray();
        TlsRecordLayer.enc24be(msg.length - 4, msg, 1);
        return msg;
    }

    private void writeCipherSuites(ByteArrayOutputStream b, List<Integer> suites, boolean includeGrease)
            throws IOException {
        int count = suites.size();
        if (includeGrease) count++; // Add one GREASE value

        byte[] cs = new byte[2 + count * 2];
        TlsRecordLayer.enc16be(count * 2, cs, 0);
        int ptr = 2;

        if (includeGrease) {
            // Add GREASE at the beginning
            int greaseValue = TlsExtension.GREASE_VALUES[RNG.nextInt(TlsExtension.GREASE_VALUES.length)];
            TlsRecordLayer.enc16be(greaseValue, cs, ptr);
            ptr += 2;
        }

        for (int suite : suites) {
            TlsRecordLayer.enc16be(suite, cs, ptr);
            ptr += 2;
        }
        b.write(cs);
    }

    private void writeExtensions(ByteArrayOutputStream ext) throws IOException {
        // SNI extension
        if (hostname != null && !hostname.isEmpty()) {
            writeSniExtension(ext, hostname);
        }

        // supported_versions extension
        if (config.isIncludeSupportedVersions()) {
            writeSupportedVersionsExtension(ext, config.getSupportedVersions());
        }

        // signature_algorithms extension
        if (config.isIncludeSignatureAlgorithms()) {
            writeSignatureAlgorithmsExtension(ext);
        }

        // supported_groups extension
        if (config.isIncludeSupportedGroups()) {
            writeSupportedGroupsExtension(ext, config.getSupportedGroups());
        }

        // key_share extension (TLS 1.3)
        if (config.isIncludeKeyShare()) {
            writeKeyShareExtension(ext);
        }

        // ec_point_formats extension
        if (config.isIncludeEcPointFormats()) {
            writeEcPointFormatsExtension(ext);
        }

        // status_request extension (OCSP stapling)
        if (config.isIncludeStatusRequest()) {
            writeStatusRequestExtension(ext);
        }

        // ALPN extension
        if (config.getAlpnProtocol() != null) {
            writeAlpnExtension(ext, config.getAlpnProtocol());
        }
    }

    private void writeSniExtension(ByteArrayOutputStream ext, String hostname) throws IOException {
        byte[] hostBytes = hostname.getBytes("ASCII");
        int dataLen = hostBytes.length + 5; // 2 (list len) + 1 (type) + 2 (name len) + name

        ext.write(0x00); ext.write(0x00); // extension type = SNI (0)
        TlsRecordLayer.enc16be(dataLen, ext);
        TlsRecordLayer.enc16be(hostBytes.length + 3, ext); // server name list length
        ext.write(0x00); // name type: host_name (0)
        TlsRecordLayer.enc16be(hostBytes.length, ext);
        ext.write(hostBytes);
    }

    private void writeSupportedVersionsExtension(ByteArrayOutputStream ext, List<Integer> versions)
            throws IOException {
        ext.write(0x00); ext.write(0x2b); // extension type = supported_versions (43)

        int dataLen = 1 + versions.size() * 2;
        TlsRecordLayer.enc16be(dataLen, ext);
        ext.write(versions.size() * 2); // versions length

        for (int version : versions) {
            ext.write(version >>> 8);
            ext.write(version);
        }
    }

    private void writeSignatureAlgorithmsExtension(ByteArrayOutputStream ext) throws IOException {
        ext.write(0x00); ext.write(0x0d); // extension type = signature_algorithms (13)

        // 9 signature algorithms
        byte[] algorithms = {
                0x08, 0x04, // rsa_pss_rsae_sha256
                0x08, 0x05, // rsa_pss_rsae_sha384
                0x08, 0x06, // rsa_pss_rsae_sha512
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0x05, 0x03, // ecdsa_secp384r1_sha384
                0x06, 0x03, // ecdsa_secp521r1_sha512
                0x04, 0x01, // rsa_pkcs1_sha256
                0x05, 0x01, // rsa_pkcs1_sha384
                0x06, 0x01  // rsa_pkcs1_sha512
        };

        TlsRecordLayer.enc16be(algorithms.length + 2, ext); // extension data length
        TlsRecordLayer.enc16be(algorithms.length, ext); // algorithms length
        ext.write(algorithms);
    }

    private void writeSupportedGroupsExtension(ByteArrayOutputStream ext, List<Integer> groups)
            throws IOException {
        ext.write(0x00); ext.write(0x0a); // extension type = supported_groups (10)

        int dataLen = 2 + groups.size() * 2;
        TlsRecordLayer.enc16be(dataLen, ext);
        TlsRecordLayer.enc16be(groups.size() * 2, ext); // groups length

        for (int group : groups) {
            ext.write(group >>> 8);
            ext.write(group);
        }
    }

    private void writeKeyShareExtension(ByteArrayOutputStream ext) throws IOException {
        try {
            // Generate X25519 key pair (preferred by most servers)
            byte[] x25519PubBytes = null;
            try {
                KeyPairGenerator x25519Kpg = KeyPairGenerator.getInstance("X25519");
                x25519KeyPair = x25519Kpg.generateKeyPair();
                // Extract raw 32-byte public key from X25519
                x25519PubBytes = extractX25519PublicKey((XECPublicKey) x25519KeyPair.getPublic());
            } catch (Exception ignored) {
                // X25519 may not be available on all JVMs
            }

            // Generate secp256r1 key pair (fallback)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            keyShareKeyPair = kpg.generateKeyPair();
            ECPublicKey ecPub = (ECPublicKey) keyShareKeyPair.getPublic();

            // Encode as uncompressed point: 04 || x || y (65 bytes for secp256r1)
            byte[] x = ecPub.getW().getAffineX().toByteArray();
            byte[] y = ecPub.getW().getAffineY().toByteArray();
            byte[] ecPoint = new byte[65];
            ecPoint[0] = 0x04;
            int xOff = x.length > 32 ? x.length - 32 : 0;
            int xLen = Math.min(x.length, 32);
            System.arraycopy(x, xOff, ecPoint, 1 + (32 - xLen), xLen);
            int yOff = y.length > 32 ? y.length - 32 : 0;
            int yLen = Math.min(y.length, 32);
            System.arraycopy(y, yOff, ecPoint, 33 + (32 - yLen), yLen);

            // key_share extension: send X25519 (preferred) + secp256r1 (fallback)
            // Each key share entry: 2 bytes group + 2 bytes length + key data
            int clientSharesLen = 0;
            if (x25519PubBytes != null) {
                clientSharesLen += 2 + 2 + x25519PubBytes.length; // X25519: 2+2+32 = 36
            }
            clientSharesLen += 2 + 2 + ecPoint.length; // secp256r1: 2+2+65 = 69

            int keyShareDataLen = 2 + clientSharesLen; // 2 for client_shares length

            ext.write(0x00); ext.write(0x33); // extension type = key_share (51)
            TlsRecordLayer.enc16be(keyShareDataLen, ext);
            TlsRecordLayer.enc16be(clientSharesLen, ext); // client_shares length

            // X25519 key share (preferred, listed first)
            if (x25519PubBytes != null) {
                ext.write(0x00); ext.write(0x1d); // named group: x25519 (0x001d)
                TlsRecordLayer.enc16be(x25519PubBytes.length, ext);
                ext.write(x25519PubBytes);
            }

            // secp256r1 key share (fallback)
            ext.write(0x00); ext.write(0x17); // named group: secp256r1 (0x0017)
            TlsRecordLayer.enc16be(ecPoint.length, ext);
            ext.write(ecPoint);
        } catch (Exception e) {
            // If key generation fails, skip key_share extension
        }
    }

    /**
     * Extract raw 32-byte public key from X25519 public key.
     * The XECPublicKey.getU() returns the u-coordinate as BigInteger;
     * we need it as 32 bytes in little-endian (RFC 7748).
     */
    private byte[] extractX25519PublicKey(XECPublicKey pub) {
        java.math.BigInteger u = pub.getU();
        byte[] uBytes = u.toByteArray();
        // BigInteger is big-endian and may have leading zero byte
        byte[] raw = new byte[32];
        // Copy right-aligned
        int srcOff = uBytes.length > 32 ? uBytes.length - 32 : 0;
        int srcLen = Math.min(uBytes.length, 32);
        System.arraycopy(uBytes, srcOff, raw, 32 - srcLen, srcLen);
        // Reverse to little-endian (RFC 7748 wire format)
        byte[] le = new byte[32];
        for (int i = 0; i < 32; i++) {
            le[i] = raw[31 - i];
        }
        return le;
    }

    private void writeEcPointFormatsExtension(ByteArrayOutputStream ext) throws IOException {
        ext.write(0x00); ext.write(0x0b); // extension type = ec_point_formats (11)
        ext.write(0x00); ext.write(0x02); // extension length
        ext.write(0x01); // formats length
        ext.write(0x00); // uncompressed
    }

    private void writeStatusRequestExtension(ByteArrayOutputStream ext) throws IOException {
        // OCSP stapling request
        ext.write(0x00); ext.write(0x05); // extension type = status_request (5)

        // status_request extension structure:
        // 1 byte: status type (1 = OCSP)
        // 2 bytes: responder_id_list length (0 = empty)
        // 2 bytes: request_extensions length (0 = empty)
        ext.write(0x00); ext.write(0x05); // extension data length
        ext.write(0x01); // status type: OCSP
        ext.write(0x00); ext.write(0x00); // responder_id_list length
        ext.write(0x00); ext.write(0x00); // request_extensions length
    }

    private void writeAlpnExtension(ByteArrayOutputStream ext, String protocol) throws IOException {
        byte[] protoBytes = protocol.getBytes("ASCII");

        ext.write(0x00); ext.write(0x10); // extension type = ALPN (16)

        int dataLen = 2 + 1 + protoBytes.length; // list len + name len + name
        TlsRecordLayer.enc16be(dataLen, ext);
        TlsRecordLayer.enc16be(1 + protoBytes.length, ext); // ALPN list length
        ext.write(protoBytes.length); // protocol name length
        ext.write(protoBytes);
    }

    /**
     * Get the record layer version to use when sending this ClientHello.
     * For TLS 1.3 compatibility, use TLS 1.0 or 1.2 as the record version.
     */
    public int getRecordVersion() {
        int version = config.getTlsVersion();
        if (version >= ClientHelloConfig.TLS_1_3) {
            return 0x0303; // TLS 1.2 for compatibility
        } else if (version >= ClientHelloConfig.TLS_1_1) {
            return version;
        } else {
            return version;
        }
    }
}
