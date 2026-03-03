package com.mps.deepviolet.api.tls;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TLS 1.3 key derivation per RFC 8446 Section 7.1.
 *
 * <p>Implements the HKDF-based key schedule used to derive handshake traffic
 * keys from the ECDH shared secret and transcript hash. Uses only
 * {@code javax.crypto.Mac} and {@code java.security.MessageDigest} —
 * no external dependencies.</p>
 *
 * <p>Key schedule flow (no PSK):
 * <pre>
 * early_secret      = HKDF-Extract(salt=zeros, ikm=zeros)
 * derived           = Derive-Secret(early_secret, "derived", SHA(empty))
 * handshake_secret  = HKDF-Extract(salt=derived, ikm=shared_secret)
 * server_hs_secret  = Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
 * server_write_key  = HKDF-Expand-Label(server_hs_secret, "key", "", key_len)
 * server_write_iv   = HKDF-Expand-Label(server_hs_secret, "iv", "", 12)
 * </pre>
 */
class Tls13KeySchedule {

    private Tls13KeySchedule() {}

    /**
     * Traffic key material for AEAD decryption.
     */
    record TrafficKeys(byte[] key, byte[] iv, String hashAlgo, String aeadAlgo) {}

    /**
     * HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
     */
    static byte[] hkdfExtract(byte[] salt, byte[] ikm, String hashAlgo)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String macAlgo = hmacAlgorithm(hashAlgo);
        Mac mac = Mac.getInstance(macAlgo);
        mac.init(new SecretKeySpec(salt, macAlgo));
        return mac.doFinal(ikm);
    }

    /**
     * HKDF-Expand-Label per RFC 8446 Section 7.1:
     * <pre>
     * struct {
     *     uint16 length = Length;
     *     opaque label&lt;7..255&gt; = "tls13 " + Label;
     *     opaque context&lt;0..255&gt; = Context;
     * } HkdfLabel;
     * HKDF-Expand-Label(Secret, Label, Context, Length) =
     *     HKDF-Expand(Secret, HkdfLabel, Length)
     * </pre>
     */
    static byte[] hkdfExpandLabel(byte[] prk, String label, byte[] context, int length,
                                   String hashAlgo)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] fullLabel = ("tls13 " + label).getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        // Build HkdfLabel structure
        byte[] hkdfLabel = new byte[2 + 1 + fullLabel.length + 1 + context.length];
        hkdfLabel[0] = (byte) (length >>> 8);
        hkdfLabel[1] = (byte) length;
        hkdfLabel[2] = (byte) fullLabel.length;
        System.arraycopy(fullLabel, 0, hkdfLabel, 3, fullLabel.length);
        hkdfLabel[3 + fullLabel.length] = (byte) context.length;
        if (context.length > 0) {
            System.arraycopy(context, 0, hkdfLabel, 4 + fullLabel.length, context.length);
        }

        return hkdfExpand(prk, hkdfLabel, length, hashAlgo);
    }

    /**
     * HKDF-Expand per RFC 5869.
     */
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length, String hashAlgo)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String macAlgo = hmacAlgorithm(hashAlgo);
        Mac mac = Mac.getInstance(macAlgo);
        mac.init(new SecretKeySpec(prk, macAlgo));

        int hashLen = mac.getMacLength();
        int n = (length + hashLen - 1) / hashLen;
        byte[] output = new byte[n * hashLen];
        byte[] t = new byte[0];

        for (int i = 1; i <= n; i++) {
            mac.reset();
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            System.arraycopy(t, 0, output, (i - 1) * hashLen, hashLen);
        }

        byte[] result = new byte[length];
        System.arraycopy(output, 0, result, 0, length);
        return result;
    }

    /**
     * Derive-Secret(Secret, Label, Messages) =
     *     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
     */
    static byte[] deriveSecret(byte[] secret, String label, byte[] transcriptHash,
                                String hashAlgo)
            throws NoSuchAlgorithmException, InvalidKeyException {
        int hashLen = hashLength(hashAlgo);
        return hkdfExpandLabel(secret, label, transcriptHash, hashLen, hashAlgo);
    }

    /**
     * Derive server handshake traffic keys from the ECDH shared secret
     * and transcript hash (ClientHello || ServerHello).
     *
     * @param sharedSecret ECDH shared secret bytes
     * @param transcriptHash Hash of ClientHello + ServerHello handshake messages
     * @param cipherSuite Negotiated TLS 1.3 cipher suite code
     * @return TrafficKeys for decrypting server handshake records
     */
    static TrafficKeys deriveHandshakeKeys(byte[] sharedSecret, byte[] transcriptHash,
                                            int cipherSuite)
            throws NoSuchAlgorithmException, InvalidKeyException {

        String hashAlgo = hashAlgorithm(cipherSuite);
        String aeadAlgo = aeadAlgorithm(cipherSuite);
        int keyLen = aeadKeyLength(cipherSuite);
        int hashLen = hashLength(hashAlgo);

        byte[] zeros = new byte[hashLen];

        // early_secret = HKDF-Extract(salt=zeros, ikm=zeros)  [no PSK]
        byte[] earlySecret = hkdfExtract(zeros, zeros, hashAlgo);

        // derived = Derive-Secret(early_secret, "derived", Hash(""))
        byte[] emptyHash = emptyHash(hashAlgo);
        byte[] derived = deriveSecret(earlySecret, "derived", emptyHash, hashAlgo);

        // handshake_secret = HKDF-Extract(salt=derived, ikm=shared_secret)
        byte[] handshakeSecret = hkdfExtract(derived, sharedSecret, hashAlgo);

        // server_handshake_traffic_secret =
        //     Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
        byte[] serverHsTrafficSecret = deriveSecret(handshakeSecret, "s hs traffic",
                transcriptHash, hashAlgo);

        // server_write_key = HKDF-Expand-Label(server_hs_secret, "key", "", key_len)
        byte[] serverWriteKey = hkdfExpandLabel(serverHsTrafficSecret, "key",
                new byte[0], keyLen, hashAlgo);

        // server_write_iv = HKDF-Expand-Label(server_hs_secret, "iv", "", 12)
        byte[] serverWriteIv = hkdfExpandLabel(serverHsTrafficSecret, "iv",
                new byte[0], 12, hashAlgo);

        return new TrafficKeys(serverWriteKey, serverWriteIv, hashAlgo, aeadAlgo);
    }

    // ==================== Cipher suite → algorithm mapping ====================

    static String hashAlgorithm(int cipherSuite) {
        return switch (cipherSuite) {
            case 0x1302 -> "SHA-384";  // TLS_AES_256_GCM_SHA384
            default -> "SHA-256";      // 0x1301, 0x1303, 0x1304, 0x1305
        };
    }

    static String aeadAlgorithm(int cipherSuite) {
        return switch (cipherSuite) {
            case 0x1303 -> "ChaCha20-Poly1305";  // TLS_CHACHA20_POLY1305_SHA256
            default -> "AES/GCM/NoPadding";       // 0x1301, 0x1302, 0x1304, 0x1305
        };
    }

    static int aeadKeyLength(int cipherSuite) {
        return switch (cipherSuite) {
            case 0x1301 -> 16;  // TLS_AES_128_GCM_SHA256
            case 0x1304 -> 16;  // TLS_AES_128_CCM_SHA256
            case 0x1305 -> 16;  // TLS_AES_128_CCM_8_SHA256
            default -> 32;      // 0x1302 (AES-256-GCM), 0x1303 (ChaCha20)
        };
    }

    private static int hashLength(String hashAlgo) {
        return "SHA-384".equals(hashAlgo) ? 48 : 32;
    }

    private static String hmacAlgorithm(String hashAlgo) {
        return "SHA-384".equals(hashAlgo) ? "HmacSHA384" : "HmacSHA256";
    }

    private static byte[] emptyHash(String hashAlgo) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(hashAlgo).digest(new byte[0]);
    }
}
