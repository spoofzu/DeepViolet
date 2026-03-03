package com.mps.deepviolet.api.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Full ServerHello message representation with ALL extensions captured.
 * Used for TLS server fingerprinting and detailed TLS analysis.
 *
 * ServerHello structure (RFC 5246 / RFC 8446):
 * - version: 2 bytes (legacy, always 0x0303 for TLS 1.3)
 * - random: 32 bytes
 * - session_id: 1 byte length + data (TLS 1.2) or echo of client session_id (TLS 1.3)
 * - cipher_suite: 2 bytes
 * - compression_method: 1 byte
 * - extensions: 2 byte length + list
 */
public class ServerHello {

    private int recordVersion;
    private int protocolVersion;
    private byte[] serverRandom;
    private byte[] sessionId;
    private int cipherSuite;
    private int compression;
    private List<TlsExtension> extensions;
    private Map<Integer, byte[]> extensionMap;
    private byte[] rawExtensions;

    // Computed fields
    private boolean isTLS13;
    private int negotiatedVersion;

    /**
     * Parse a ServerHello message from raw bytes.
     * @param data The ServerHello message body (without handshake header)
     * @param recordVersion The record layer version
     */
    public ServerHello(byte[] data, int recordVersion) throws TlsException {
        this.recordVersion = recordVersion;
        this.extensions = new ArrayList<>();
        this.extensionMap = new HashMap<>();
        parse(data);
    }

    private void parse(byte[] buf) throws TlsException {
        int ptr = 0;

        // Protocol version (2 bytes)
        if (ptr + 2 > buf.length) {
            throw new TlsException("Invalid ServerHello: too short for version");
        }
        protocolVersion = TlsRecordLayer.dec16be(buf, ptr);
        ptr += 2;

        // Server random (32 bytes)
        if (ptr + 32 > buf.length) {
            throw new TlsException("Invalid ServerHello: too short for random");
        }
        serverRandom = new byte[32];
        System.arraycopy(buf, ptr, serverRandom, 0, 32);
        ptr += 32;

        // Session ID
        if (ptr + 1 > buf.length) {
            throw new TlsException("Invalid ServerHello: too short for session ID length");
        }
        int sessionIdLen = buf[ptr] & 0xFF;
        ptr += 1;
        if (ptr + sessionIdLen > buf.length) {
            throw new TlsException("Invalid ServerHello: session ID extends past message");
        }
        sessionId = new byte[sessionIdLen];
        System.arraycopy(buf, ptr, sessionId, 0, sessionIdLen);
        ptr += sessionIdLen;

        // Cipher suite (2 bytes)
        if (ptr + 2 > buf.length) {
            throw new TlsException("Invalid ServerHello: too short for cipher suite");
        }
        cipherSuite = TlsRecordLayer.dec16be(buf, ptr);
        ptr += 2;

        // Compression method (1 byte)
        if (ptr + 1 > buf.length) {
            throw new TlsException("Invalid ServerHello: too short for compression");
        }
        compression = buf[ptr] & 0xFF;
        ptr += 1;

        // Extensions (optional)
        negotiatedVersion = protocolVersion;
        isTLS13 = false;

        if (ptr + 2 <= buf.length) {
            int extTotalLen = TlsRecordLayer.dec16be(buf, ptr);
            ptr += 2;
            int extEnd = ptr + extTotalLen;

            // Store raw extensions for fingerprint hashing
            if (extTotalLen > 0) {
                rawExtensions = new byte[extTotalLen];
                System.arraycopy(buf, ptr, rawExtensions, 0, extTotalLen);
            }

            // Parse extensions
            while (ptr + 4 <= extEnd && ptr + 4 <= buf.length) {
                int extType = TlsRecordLayer.dec16be(buf, ptr);
                ptr += 2;
                int extLen = TlsRecordLayer.dec16be(buf, ptr);
                ptr += 2;

                if (ptr + extLen > buf.length) {
                    break;
                }

                byte[] extData = new byte[extLen];
                System.arraycopy(buf, ptr, extData, 0, extLen);

                TlsExtension ext = new TlsExtension(extType, extData);
                extensions.add(ext);
                extensionMap.put(extType, extData);

                // Check for supported_versions extension (TLS 1.3)
                if (extType == TlsExtension.SUPPORTED_VERSIONS && extLen >= 2) {
                    int sv = TlsRecordLayer.dec16be(extData, 0);
                    if (sv >= 0x0304) {
                        isTLS13 = true;
                        negotiatedVersion = sv;
                    }
                }

                ptr += extLen;
            }
        }

        // Final TLS 1.3 check based on version
        if (negotiatedVersion >= 0x0304) {
            isTLS13 = true;
        }
    }

    // ==================== Getters ====================

    public int getRecordVersion() {
        return recordVersion;
    }

    public int getProtocolVersion() {
        return protocolVersion;
    }

    public int getNegotiatedVersion() {
        return negotiatedVersion;
    }

    public byte[] getServerRandom() {
        return serverRandom.clone();
    }

    public byte[] getSessionId() {
        return sessionId.clone();
    }

    public int getCipherSuite() {
        return cipherSuite;
    }

    public int getCompression() {
        return compression;
    }

    public List<TlsExtension> getExtensions() {
        return Collections.unmodifiableList(extensions);
    }

    public Map<Integer, byte[]> getExtensionMap() {
        Map<Integer, byte[]> copy = new HashMap<>();
        for (Map.Entry<Integer, byte[]> entry : extensionMap.entrySet()) {
            copy.put(entry.getKey(), entry.getValue().clone());
        }
        return copy;
    }

    public byte[] getRawExtensions() {
        return rawExtensions != null ? rawExtensions.clone() : new byte[0];
    }

    public boolean isTLS13() {
        return isTLS13;
    }

    /**
     * Check if a specific extension is present.
     */
    public boolean hasExtension(int type) {
        return extensionMap.containsKey(type);
    }

    /**
     * Get extension data by type.
     * @return Extension data, or null if not present
     */
    public byte[] getExtensionData(int type) {
        byte[] data = extensionMap.get(type);
        return data != null ? data.clone() : null;
    }

    // ==================== Key Share Helpers ====================

    /**
     * Get the server's selected key share named group.
     * Parses the key_share extension (type 0x0033).
     *
     * @return Named group code (e.g., 0x001d for X25519, 0x0017 for secp256r1),
     *         or -1 if no key_share extension present
     */
    public int getKeyShareGroup() {
        byte[] data = extensionMap.get(TlsExtension.KEY_SHARE);
        if (data == null || data.length < 4) {
            return -1;
        }
        return TlsRecordLayer.dec16be(data, 0);
    }

    /**
     * Get the server's key share public key bytes.
     * Parses the key_share extension (type 0x0033).
     *
     * @return Raw public key bytes, or null if no key_share extension present
     */
    public byte[] getKeySharePublicKey() {
        byte[] data = extensionMap.get(TlsExtension.KEY_SHARE);
        if (data == null || data.length < 4) {
            return null;
        }
        int keyLen = TlsRecordLayer.dec16be(data, 2);
        if (4 + keyLen > data.length) {
            return null;
        }
        byte[] key = new byte[keyLen];
        System.arraycopy(data, 4, key, 0, keyLen);
        return key;
    }

    // ==================== Fingerprint Support Methods ====================

    /**
     * Get the 3-character fingerprint code for this ServerHello.
     * Format: [cipher-char][version-char][extension-char]
     *
     * <p>Used for TLS server fingerprinting to characterize the server's
     * cipher selection and extension behavior.</p>
     *
     * @return 3-character code representing cipher, version, and extension count
     */
    public String getFingerprintCode() {
        StringBuilder code = new StringBuilder(3);

        // Character 1: Cipher suite encoding
        code.append(getCipherChar());

        // Character 2: Version encoding
        code.append(getVersionChar());

        // Character 3: Extension encoding
        code.append(getExtensionChar());

        return code.toString();
    }

    private char getCipherChar() {
        // Map cipher suites to single characters for JARM fingerprint
        // Based on Salesforce's JARM implementation
        int cipher = cipherSuite;

        // TLS 1.3 ciphers
        if (cipher == 0x1301) return 'a'; // TLS_AES_128_GCM_SHA256
        if (cipher == 0x1302) return 'b'; // TLS_AES_256_GCM_SHA384
        if (cipher == 0x1303) return 'c'; // TLS_CHACHA20_POLY1305_SHA256
        if (cipher == 0x1304) return 'd'; // TLS_AES_128_CCM_SHA256
        if (cipher == 0x1305) return 'e'; // TLS_AES_128_CCM_8_SHA256

        // Common TLS 1.2 ECDHE ciphers
        if (cipher == 0xc02c) return 'f'; // ECDHE_ECDSA_AES_256_GCM
        if (cipher == 0xc02b) return 'g'; // ECDHE_ECDSA_AES_128_GCM
        if (cipher == 0xc030) return 'h'; // ECDHE_RSA_AES_256_GCM
        if (cipher == 0xc02f) return 'i'; // ECDHE_RSA_AES_128_GCM
        if (cipher == 0xc024) return 'j'; // ECDHE_ECDSA_AES_256_CBC
        if (cipher == 0xc023) return 'k'; // ECDHE_ECDSA_AES_128_CBC
        if (cipher == 0xc028) return 'l'; // ECDHE_RSA_AES_256_CBC
        if (cipher == 0xc027) return 'm'; // ECDHE_RSA_AES_128_CBC
        if (cipher == 0xc00a) return 'n'; // ECDHE_ECDSA_3DES
        if (cipher == 0xc009) return 'o'; // ECDHE_ECDSA_AES_128
        if (cipher == 0xc014) return 'p'; // ECDHE_RSA_3DES
        if (cipher == 0xc013) return 'q'; // ECDHE_RSA_AES_128

        // DHE ciphers
        if (cipher == 0x009f) return 'r'; // DHE_RSA_AES_256_GCM
        if (cipher == 0x009e) return 's'; // DHE_RSA_AES_128_GCM
        if (cipher == 0x0067) return 't'; // DHE_RSA_AES_128_CBC
        if (cipher == 0x006b) return 'u'; // DHE_RSA_AES_256_CBC

        // RSA ciphers
        if (cipher == 0x009d) return 'v'; // RSA_AES_256_GCM
        if (cipher == 0x009c) return 'w'; // RSA_AES_128_GCM
        if (cipher == 0x003d) return 'x'; // RSA_AES_256_CBC
        if (cipher == 0x003c) return 'y'; // RSA_AES_128_CBC
        if (cipher == 0x0035) return 'z'; // RSA_AES_256
        if (cipher == 0x002f) return '0'; // RSA_AES_128

        // Unknown cipher
        return '|';
    }

    private char getVersionChar() {
        int version = negotiatedVersion;

        if (version == 0x0304) return '3'; // TLS 1.3
        if (version == 0x0303) return '2'; // TLS 1.2
        if (version == 0x0302) return '1'; // TLS 1.1
        if (version == 0x0301) return '0'; // TLS 1.0
        if (version == 0x0300) return 's'; // SSL 3.0

        return '|'; // Unknown
    }

    private char getExtensionChar() {
        // Count significant extensions (non-GREASE)
        int count = 0;
        for (TlsExtension ext : extensions) {
            if (!ext.isGrease()) {
                count++;
            }
        }

        // Map count to character
        if (count == 0) return '0';
        if (count <= 9) return (char) ('0' + count);
        if (count <= 35) return (char) ('a' + count - 10);
        return '|'; // Too many extensions
    }

    /**
     * Get the SHA256 hash of the raw extensions (truncated to 16 bytes).
     * Used for TLS server fingerprint generation.
     */
    public byte[] getExtensionsHash() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (rawExtensions != null) {
                md.update(rawExtensions);
            }
            byte[] hash = md.digest();
            return Arrays.copyOf(hash, 16); // Truncate to 16 bytes
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Get the extension types in order (for TLS server fingerprinting).
     * Excludes GREASE values.
     */
    public List<Integer> getExtensionTypes() {
        List<Integer> types = new ArrayList<>();
        for (TlsExtension ext : extensions) {
            if (!ext.isGrease()) {
                types.add(ext.getType());
            }
        }
        return types;
    }

    // ==================== Utility Methods ====================

    /**
     * Get human-readable version string.
     */
    public String getVersionString() {
        int version = negotiatedVersion;
        if (version == 0x0304) return "TLSv1.3";
        if (version == 0x0303) return "TLSv1.2";
        if (version == 0x0302) return "TLSv1.1";
        if (version == 0x0301) return "TLSv1.0";
        if (version == 0x0300) return "SSLv3";
        return String.format("Unknown(0x%04x)", version);
    }

    /**
     * Get cipher suite as hex string.
     */
    public String getCipherSuiteHex() {
        return String.format("0x%04x", cipherSuite);
    }

    @Override
    public String toString() {
        return String.format("ServerHello[version=%s, cipher=%s, extensions=%d, TLS1.3=%b]",
                getVersionString(), getCipherSuiteHex(), extensions.size(), isTLS13);
    }
}
