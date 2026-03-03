package com.mps.deepviolet.api.tls;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AEAD decryption for TLS 1.3 encrypted records per RFC 8446 Section 5.2.
 *
 * <p>TLS 1.3 encrypts handshake messages as APPLICATION_DATA records.
 * Each record is decrypted using AEAD with:</p>
 * <ul>
 *   <li>nonce = iv XOR sequence_number (big-endian, left-padded to 12 bytes)</li>
 *   <li>AAD = 5-byte record header (type=23, version=0x0303, length)</li>
 *   <li>plaintext ends with content_type byte + optional zero padding</li>
 * </ul>
 */
class Tls13RecordProtection {

    private Tls13RecordProtection() {}

    /**
     * Decrypted record content with actual content type.
     */
    record DecryptedRecord(int contentType, byte[] data) {}

    /**
     * Decrypt a TLS 1.3 encrypted record.
     *
     * @param encrypted  Encrypted payload (ciphertext + auth tag)
     * @param recordHeader 5-byte TLS record header (type, version, length)
     * @param seqNum     Record sequence number (starts at 0)
     * @param keys       Traffic keys from key schedule
     * @return Decrypted record with actual content type
     * @throws TlsException if decryption fails
     */
    static DecryptedRecord decryptRecord(byte[] encrypted, byte[] recordHeader,
                                          long seqNum, Tls13KeySchedule.TrafficKeys keys)
            throws TlsException {
        try {
            // Build nonce: iv XOR sequence_number (left-padded to 12 bytes)
            byte[] nonce = new byte[12];
            System.arraycopy(keys.iv(), 0, nonce, 0, 12);
            for (int i = 0; i < 8; i++) {
                nonce[11 - i] ^= (byte) ((seqNum >>> (i * 8)) & 0xFF);
            }

            // Decrypt
            byte[] plaintext;
            String aeadAlgo = keys.aeadAlgo();

            if ("ChaCha20-Poly1305".equals(aeadAlgo)) {
                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(keys.key(), "ChaCha20"),
                        new IvParameterSpec(nonce));
                cipher.updateAAD(recordHeader);
                plaintext = cipher.doFinal(encrypted);
            } else {
                // AES-GCM (128 or 256 bit)
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(keys.key(), "AES"),
                        new GCMParameterSpec(128, nonce)); // 128-bit auth tag
                cipher.updateAAD(recordHeader);
                plaintext = cipher.doFinal(encrypted);
            }

            // Strip trailing zeros and content_type byte
            // RFC 8446 Section 5.4: plaintext ends with ContentType + zeros
            int end = plaintext.length - 1;
            while (end >= 0 && plaintext[end] == 0) {
                end--;
            }
            if (end < 0) {
                throw new TlsException("Decrypted record has no content type");
            }

            int actualType = plaintext[end] & 0xFF;
            byte[] content = new byte[end];
            System.arraycopy(plaintext, 0, content, 0, end);

            return new DecryptedRecord(actualType, content);

        } catch (GeneralSecurityException e) {
            throw new TlsException("Failed to decrypt TLS 1.3 record: " + e.getMessage(), e);
        }
    }
}
